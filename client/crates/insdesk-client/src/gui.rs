//! Graphical controller built on `egui`/`eframe`.
//!
//! Enabled with `--features gui` (needs OpenGL + a window system, so it is off
//! in headless CI). The UI:
//!
//! * renders the live remote screen into a texture,
//! * forwards mouse movement, clicks, scroll, typed text and special keys to the
//!   host ("control PC"),
//! * shows a status bar (host, latency, a prominent UAC/secure-desktop banner),
//! * offers quality/FPS controls, a keyframe button and clipboard push,
//! * lists a remote directory for file operations.
//!
//! The async controller engine runs on a background Tokio runtime; the GUI
//! thread talks to it over the handle's command/event channels.

use crate::connect::{self, ConnectOpts};
use insdesk_core::controller::{ControllerCommand, ControllerEvent};
use insdesk_proto::{ClipboardData, DirEntry, InputEvent, Key, MouseButton, QualityHint};
use std::sync::Arc;
use tokio::sync::mpsc;

type Setup = (
    mpsc::Sender<ControllerCommand>,
    mpsc::Receiver<ControllerEvent>,
    String,
    u64,
    u32,
    u32,
);

/// Entry point for the GUI controller.
pub fn run(opts: ConnectOpts) -> anyhow::Result<()> {
    // Bring up the connection on a background runtime and ship the live handle
    // to this (UI) thread.
    let (setup_tx, setup_rx) = std::sync::mpsc::channel::<Result<Setup, String>>();
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => {
                let _ = setup_tx.send(Err(e.to_string()));
                return;
            }
        };
        rt.block_on(async move {
            match connect::establish(&opts).await {
                Ok(handle) => {
                    let setup = (
                        handle.commands.clone(),
                        handle.events,
                        handle.host_name.clone(),
                        handle.host_id,
                        handle.width,
                        handle.height,
                    );
                    if setup_tx.send(Ok(setup)).is_ok() {
                        // Keep the runtime (and the engine's driver task) alive.
                        std::future::pending::<()>().await;
                    }
                }
                Err(e) => {
                    let _ = setup_tx.send(Err(e.to_string()));
                }
            }
        });
    });

    let (cmd, events, host_name, host_id, width, height) = match setup_rx.recv() {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => anyhow::bail!("connection failed: {e}"),
        Err(_) => anyhow::bail!("connection setup aborted"),
    };

    let app = InsDeskApp::new(cmd, events, host_name, host_id, width, height);
    let options = eframe::NativeOptions::default();
    eframe::run_native("InsDesk", options, Box::new(|_cc| Ok(Box::new(app))))
        .map_err(|e| anyhow::anyhow!("eframe error: {e}"))
}

struct InsDeskApp {
    cmd: mpsc::Sender<ControllerCommand>,
    events: mpsc::Receiver<ControllerEvent>,
    host_name: String,
    host_id: u64,
    width: u32,
    height: u32,

    texture: Option<egui::TextureHandle>,
    latency_ms: Option<u64>,
    secure_desktop: bool,
    status: String,

    quality: u8,
    fps: u8,
    last_modifiers: egui::Modifiers,

    remote_path: String,
    listing: Vec<DirEntry>,
    clipboard_draft: String,
}

impl InsDeskApp {
    fn new(
        cmd: mpsc::Sender<ControllerCommand>,
        events: mpsc::Receiver<ControllerEvent>,
        host_name: String,
        host_id: u64,
        width: u32,
        height: u32,
    ) -> Self {
        InsDeskApp {
            cmd,
            events,
            host_name,
            host_id,
            width,
            height,
            texture: None,
            latency_ms: None,
            secure_desktop: false,
            status: "connected".into(),
            quality: 80,
            fps: 30,
            last_modifiers: egui::Modifiers::default(),
            remote_path: ".".into(),
            listing: Vec::new(),
            clipboard_draft: String::new(),
        }
    }

    fn send(&self, cmd: ControllerCommand) {
        let _ = self.cmd.try_send(cmd);
    }

    fn drain_events(&mut self, ctx: &egui::Context) {
        while let Ok(event) = self.events.try_recv() {
            match event {
                ControllerEvent::Frame { width, height, rgba, .. } => {
                    let image = egui::ColorImage::from_rgba_unmultiplied(
                        [width as usize, height as usize],
                        &rgba,
                    );
                    match &mut self.texture {
                        Some(tex) => tex.set(image, egui::TextureOptions::LINEAR),
                        None => {
                            self.texture =
                                Some(ctx.load_texture("remote", image, egui::TextureOptions::LINEAR));
                        }
                    }
                }
                ControllerEvent::Latency { millis } => self.latency_ms = Some(millis),
                ControllerEvent::SecureDesktop(active) => self.secure_desktop = active,
                ControllerEvent::DirListing { path, entries, error } => {
                    self.remote_path = path;
                    if let Some(e) = error {
                        self.status = format!("ls error: {e}");
                    } else {
                        self.listing = entries;
                    }
                }
                ControllerEvent::Clipboard(ClipboardData::Text(t)) => {
                    self.status = format!("remote clipboard: {} chars", t.len());
                }
                ControllerEvent::TransferCompleted { transfer, ok, detail } => {
                    self.status = format!("transfer {transfer} {}: {detail}", if ok { "ok" } else { "FAILED" });
                }
                ControllerEvent::Disconnected { reason } => {
                    self.status = format!("disconnected: {}", reason.unwrap_or_default());
                }
                ControllerEvent::Error(e) => self.status = format!("error: {e}"),
                _ => {}
            }
        }
    }

    /// Forward input happening over the remote image to the host, mapping
    /// screen coordinates back to host pixels.
    fn forward_input(&mut self, ui: &egui::Ui, image_rect: egui::Rect) {
        let input = ui.ctx().input(|i| i.clone());

        // Modifier changes → press/release the matching keys.
        let m = input.modifiers;
        for (now, was, key) in [
            (m.shift, self.last_modifiers.shift, Key::Shift),
            (m.ctrl, self.last_modifiers.ctrl, Key::Control),
            (m.alt, self.last_modifiers.alt, Key::Alt),
            (m.command, self.last_modifiers.command, Key::Meta),
        ] {
            if now != was {
                self.send(ControllerCommand::Input(InputEvent::Key { key, down: now }));
            }
        }
        self.last_modifiers = m;

        let to_host = |pos: egui::Pos2| -> Option<(i32, i32)> {
            if !image_rect.contains(pos) || image_rect.width() <= 0.0 || image_rect.height() <= 0.0 {
                return None;
            }
            let fx = (pos.x - image_rect.left()) / image_rect.width();
            let fy = (pos.y - image_rect.top()) / image_rect.height();
            Some(((fx * self.width as f32) as i32, (fy * self.height as f32) as i32))
        };

        for ev in &input.events {
            match ev {
                egui::Event::PointerMoved(pos) => {
                    if let Some((x, y)) = to_host(*pos) {
                        self.send(ControllerCommand::Input(InputEvent::MouseMove { x, y }));
                    }
                }
                egui::Event::PointerButton { pos, button, pressed, .. } => {
                    if to_host(*pos).is_some() {
                        if let Some(b) = map_button(*button) {
                            self.send(ControllerCommand::Input(InputEvent::MouseButton { button: b, down: *pressed }));
                        }
                    }
                }
                egui::Event::MouseWheel { delta, .. } => {
                    self.send(ControllerCommand::Input(InputEvent::MouseScroll {
                        dx: delta.x as i32,
                        dy: delta.y as i32,
                    }));
                }
                egui::Event::Text(text) => {
                    for ch in text.chars() {
                        self.send(ControllerCommand::Input(InputEvent::Text { ch }));
                    }
                }
                egui::Event::Key { key, pressed, .. } => {
                    if let Some(k) = map_key(*key) {
                        self.send(ControllerCommand::Input(InputEvent::Key { key: k, down: *pressed }));
                    }
                }
                _ => {}
            }
        }
    }
}

impl eframe::App for InsDeskApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_events(ctx);

        egui::TopBottomPanel::top("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.strong(format!("{} (id {})", self.host_name, self.host_id));
                ui.separator();
                match self.latency_ms {
                    Some(ms) => ui.label(format!("{ms} ms")),
                    None => ui.label("… ms"),
                };
                ui.separator();
                ui.label(&self.status);
            });
            if self.secure_desktop {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 60, 60),
                    "⚠ UAC secure desktop active — you are viewing & controlling the elevation prompt",
                );
            }
        });

        egui::SidePanel::right("controls").default_width(260.0).show(ctx, |ui| {
            ui.heading("Session");
            if ui.button("Request keyframe").clicked() {
                self.send(ControllerCommand::RequestKeyframe);
            }
            if ui.button("Ping").clicked() {
                self.send(ControllerCommand::Ping);
            }
            ui.add(egui::Slider::new(&mut self.quality, 1..=100).text("quality"));
            ui.add(egui::Slider::new(&mut self.fps, 1..=60).text("fps"));
            if ui.button("Apply quality").clicked() {
                self.send(ControllerCommand::SetQuality(QualityHint { quality: self.quality, max_fps: self.fps }));
            }

            ui.separator();
            ui.heading("Elevation");
            if ui.button("Request elevation (UAC)").clicked() {
                self.send(ControllerCommand::RequestElevation("operator request".into()));
            }

            ui.separator();
            ui.heading("Clipboard");
            ui.text_edit_multiline(&mut self.clipboard_draft);
            if ui.button("Send to host").clicked() {
                self.send(ControllerCommand::SendClipboard(ClipboardData::Text(self.clipboard_draft.clone())));
            }

            ui.separator();
            ui.heading("Remote files");
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut self.remote_path);
                if ui.button("List").clicked() {
                    self.send(ControllerCommand::ListDir(self.remote_path.clone()));
                }
            });
            egui::ScrollArea::vertical().max_height(240.0).show(ui, |ui| {
                for entry in &self.listing {
                    let icon = if entry.is_dir { "📁" } else { "📄" };
                    ui.label(format!("{icon} {}  ({} B)", entry.name, entry.size));
                }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(tex) = &self.texture {
                let avail = ui.available_size();
                let aspect = self.width as f32 / self.height as f32;
                let mut size = avail;
                if size.x / size.y > aspect {
                    size.x = size.y * aspect;
                } else {
                    size.y = size.x / aspect;
                }
                let response =
                    ui.add(egui::Image::new(egui::load::SizedTexture::new(tex.id(), size)).sense(egui::Sense::click_and_drag()));
                self.forward_input(ui, response.rect);
            } else {
                ui.centered_and_justified(|ui| {
                    ui.label("waiting for first frame…");
                });
            }
        });

        // Drive a steady repaint so the stream stays live.
        ctx.request_repaint_after(std::time::Duration::from_millis(16));
    }
}

fn map_button(b: egui::PointerButton) -> Option<MouseButton> {
    match b {
        egui::PointerButton::Primary => Some(MouseButton::Left),
        egui::PointerButton::Secondary => Some(MouseButton::Right),
        egui::PointerButton::Middle => Some(MouseButton::Middle),
        _ => None,
    }
}

fn map_key(k: egui::Key) -> Option<Key> {
    use egui::Key as E;
    Some(match k {
        E::Enter => Key::Enter,
        E::Escape => Key::Escape,
        E::Backspace => Key::Backspace,
        E::Tab => Key::Tab,
        E::Space => Key::Space,
        E::Delete => Key::Delete,
        E::Home => Key::Home,
        E::End => Key::End,
        E::PageUp => Key::PageUp,
        E::PageDown => Key::PageDown,
        E::ArrowLeft => Key::Left,
        E::ArrowRight => Key::Right,
        E::ArrowUp => Key::Up,
        E::ArrowDown => Key::Down,
        _ => return None,
    })
}
