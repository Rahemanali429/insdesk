//! InsDesk desktop application (AnyDesk-style), built on `egui`/`eframe`.
//!
//! One window does both halves of remote desktop:
//!
//! * **This Desk** — on launch the app loads/creates this machine's identity,
//!   shows its 9-digit **Device ID** and a freshly generated **password**, and
//!   runs the host in the background so anyone given that ID + password can
//!   connect in and view/control this machine.
//! * **Remote Desk** — type a partner's Device ID and password, click
//!   **Connect**, and the window switches to a live view of their screen with
//!   full mouse/keyboard control, a status bar, quality controls, clipboard
//!   push and a remote file list.
//!
//! Enabled with `--features gui` (needs OpenGL + a window system, so it cannot
//! build or run on headless CI). Add `--features desktop` for real screen
//! capture, input injection and clipboard in the background host.

use crate::connect::ConnectOpts;
use insdesk_core::backends::default_host_backends;
use insdesk_core::controller::{self, ControllerCommand, ControllerEvent, ControllerHandle};
use insdesk_core::host::{self, HostConfig};
use insdesk_crypto::Identity;
use insdesk_net::{perform_handshake, relay, spawn_session, HandshakeRole};
use insdesk_proto::{ClipboardData, DirEntry, InputEvent, Key, MouseButton, QualityHint};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// A request from the UI to open an outgoing session.
struct ConnectRequest {
    partner_id: u64,
    password: String,
}

/// Status of the always-on background host.
#[derive(Clone)]
enum HostStatus {
    Connecting,
    Online,
    Serving,
    Error(String),
}

fn set_status(slot: &Arc<Mutex<HostStatus>>, value: HostStatus) {
    if let Ok(mut s) = slot.lock() {
        *s = value;
    }
}

/// Launch the desktop app.
pub fn run(opts: ConnectOpts) -> anyhow::Result<()> {
    let identity = insdesk_core::load_or_create(&opts.key)?;
    let device_id = identity.device_id();
    let public_hex = identity.public_hex();
    let relay_addr = opts.relay.clone().unwrap_or_else(|| "127.0.0.1:9510".to_string());
    let display_name = opts.name.clone();
    let password = Arc::new(Mutex::new(
        opts.password.clone().unwrap_or_else(|| insdesk_core::random_password(8)),
    ));
    let status = Arc::new(Mutex::new(HostStatus::Connecting));

    let (connect_tx, connect_rx) = mpsc::channel::<ConnectRequest>(8);
    let (session_tx, session_rx) = mpsc::channel::<Result<ControllerHandle, String>>(8);

    // Background Tokio runtime: the always-on host service plus a worker that
    // establishes outgoing sessions on demand.
    {
        let identity = Arc::new(identity);
        let relay_addr = relay_addr.clone();
        let display_name = display_name.clone();
        let password = password.clone();
        let status = status.clone();
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(e) => {
                    set_status(&status, HostStatus::Error(e.to_string()));
                    return;
                }
            };
            rt.block_on(async move {
                tokio::spawn(host_service(
                    relay_addr.clone(),
                    identity.clone(),
                    display_name.clone(),
                    password.clone(),
                    status.clone(),
                ));
                let mut connect_rx = connect_rx;
                while let Some(req) = connect_rx.recv().await {
                    let identity = identity.clone();
                    let relay_addr = relay_addr.clone();
                    let name = display_name.clone();
                    let out = session_tx.clone();
                    tokio::spawn(async move {
                        let res = establish_outgoing(&relay_addr, &identity, &name, req)
                            .await
                            .map_err(|e| e.to_string());
                        let _ = out.send(res).await;
                    });
                }
            });
        });
    }

    let app = InsDeskApp::new(
        device_id, public_hex, relay_addr, password, status, connect_tx, session_rx, opts.id,
    );
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([980.0, 660.0])
            .with_min_inner_size([720.0, 480.0])
            .with_title("InsDesk"),
        ..Default::default()
    };
    eframe::run_native("InsDesk", options, Box::new(|_cc| Ok(Box::new(app))))
        .map_err(|e| anyhow::anyhow!("eframe error: {e}"))
}

/// The always-on background host: register on the relay and serve whoever
/// connects, using the current password.
async fn host_service(
    relay_addr: String,
    identity: Arc<Identity>,
    display_name: String,
    password: Arc<Mutex<String>>,
    status: Arc<Mutex<HostStatus>>,
) {
    let device_id = identity.device_id();
    loop {
        set_status(&status, HostStatus::Connecting);
        match relay::register_host(&relay_addr, device_id).await {
            Ok(mut stream) => {
                set_status(&status, HostStatus::Online);
                if relay::wait_for_peer(&mut stream).await.is_ok() {
                    set_status(&status, HostStatus::Serving);
                    if let Ok(est) =
                        perform_handshake(&mut stream, HandshakeRole::Responder, &identity).await
                    {
                        let (transport, meta) = est.into_parts();
                        let session = spawn_session(stream, transport, 32);
                        let pw = password.lock().map(|p| p.clone()).unwrap_or_default();
                        let cfg = HostConfig {
                            display_name: display_name.clone(),
                            password: Some(pw),
                            auto_accept: true,
                            allow_input: true,
                            allow_file_transfer: true,
                            allow_secure_desktop_control: true,
                            tile_size: 64,
                            quality: 80,
                            max_fps: 30,
                        };
                        let backends = default_host_backends(1280, 720, None);
                        if let Err(e) = host::run(session, &meta, cfg, backends).await {
                            tracing::warn!("host session ended: {e}");
                        }
                    }
                    set_status(&status, HostStatus::Online);
                }
            }
            Err(e) => {
                set_status(&status, HostStatus::Error(e.to_string()));
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        }
    }
}

/// Dial a partner and bring up a controller session.
async fn establish_outgoing(
    relay_addr: &str,
    identity: &Identity,
    name: &str,
    req: ConnectRequest,
) -> anyhow::Result<ControllerHandle> {
    let mut stream = relay::connect_to_host(relay_addr, req.partner_id).await?;
    let est = perform_handshake(&mut stream, HandshakeRole::Initiator, identity).await?;
    let (transport, meta) = est.into_parts();
    let session = spawn_session(stream, transport, 32);
    let cfg = controller::ControllerConfig {
        display_name: name.to_string(),
        expected_id: Some(req.partner_id),
        password: Some(req.password),
        initial_quality: QualityHint::default(),
    };
    controller::connect(session, &meta, cfg).await
}

// ---------------------------------------------------------------------------
// The app
// ---------------------------------------------------------------------------

struct InsDeskApp {
    device_id_fmt: String,
    public_hex: String,
    relay_addr: String,
    password: Arc<Mutex<String>>,
    status: Arc<Mutex<HostStatus>>,

    connect_tx: mpsc::Sender<ConnectRequest>,
    session_rx: mpsc::Receiver<Result<ControllerHandle, String>>,

    partner_id: String,
    partner_password: String,
    connecting: bool,
    last_error: Option<String>,

    session: Option<SessionView>,
}

impl InsDeskApp {
    #[allow(clippy::too_many_arguments)]
    fn new(
        device_id: u64,
        public_hex: String,
        relay_addr: String,
        password: Arc<Mutex<String>>,
        status: Arc<Mutex<HostStatus>>,
        connect_tx: mpsc::Sender<ConnectRequest>,
        session_rx: mpsc::Receiver<Result<ControllerHandle, String>>,
        prefill_id: Option<u64>,
    ) -> Self {
        InsDeskApp {
            device_id_fmt: group_digits(device_id),
            public_hex,
            relay_addr,
            password,
            status,
            connect_tx,
            session_rx,
            partner_id: prefill_id.map(|id| id.to_string()).unwrap_or_default(),
            partner_password: String::new(),
            connecting: false,
            last_error: None,
            session: None,
        }
    }

    fn start_connect(&mut self) {
        let digits: String = self.partner_id.chars().filter(|c| c.is_ascii_digit()).collect();
        match digits.parse::<u64>() {
            Ok(partner_id) => {
                self.last_error = None;
                self.connecting = true;
                let req = ConnectRequest { partner_id, password: self.partner_password.clone() };
                if self.connect_tx.try_send(req).is_err() {
                    self.connecting = false;
                    self.last_error = Some("connection worker is busy; try again".into());
                }
            }
            Err(_) => self.last_error = Some("enter a numeric Device ID".into()),
        }
    }

    fn poll_session_result(&mut self) {
        if let Ok(result) = self.session_rx.try_recv() {
            self.connecting = false;
            match result {
                Ok(handle) => {
                    self.session = Some(SessionView::new(handle));
                    self.last_error = None;
                }
                Err(e) => self.last_error = Some(e),
            }
        }
    }

    fn home_ui(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("home_top").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading("InsDesk");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let (label, color) = self.status_badge();
                    ui.colored_label(color, label);
                });
            });
            ui.add_space(6.0);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(8.0);
            ui.columns(2, |cols| {
                self.this_desk_panel(&mut cols[0]);
                self.remote_desk_panel(&mut cols[1]);
            });
            ui.add_space(12.0);
            ui.separator();
            ui.horizontal(|ui| {
                ui.label("Relay:");
                ui.monospace(&self.relay_addr);
            });
        });
    }

    fn status_badge(&self) -> (String, egui::Color32) {
        match self.status.lock().map(|s| s.clone()) {
            Ok(HostStatus::Online) => ("● Ready for incoming".into(), egui::Color32::from_rgb(60, 180, 90)),
            Ok(HostStatus::Serving) => ("● Serving a session".into(), egui::Color32::from_rgb(70, 140, 220)),
            Ok(HostStatus::Connecting) => ("● Connecting to relay…".into(), egui::Color32::from_rgb(200, 170, 60)),
            Ok(HostStatus::Error(e)) => (format!("● Relay error: {e}"), egui::Color32::from_rgb(210, 70, 70)),
            Err(_) => ("● unknown".into(), egui::Color32::GRAY),
        }
    }

    fn this_desk_panel(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.set_min_height(240.0);
            ui.heading("This Desk");
            ui.label("Give these to someone so they can connect to this computer.");
            ui.add_space(10.0);

            ui.label("Your Device ID");
            ui.label(egui::RichText::new(&self.device_id_fmt).monospace().size(30.0).strong());
            ui.add_space(10.0);

            ui.label("Password");
            ui.horizontal(|ui| {
                let pw = self.password.lock().map(|p| p.clone()).unwrap_or_default();
                ui.label(egui::RichText::new(pw).monospace().size(24.0).strong());
                if ui.button("🔄 New").on_hover_text("Generate a new password").clicked() {
                    if let Ok(mut p) = self.password.lock() {
                        *p = insdesk_core::random_password(8);
                    }
                }
            });
            ui.add_space(10.0);

            ui.label(
                egui::RichText::new(format!("key {}…", &self.public_hex[..self.public_hex.len().min(16)]))
                    .small()
                    .weak(),
            );
        });
    }

    fn remote_desk_panel(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.set_min_height(240.0);
            ui.heading("Remote Desk");
            ui.label("Connect to another computer by its Device ID.");
            ui.add_space(10.0);

            ui.label("Partner Device ID");
            ui.add(egui::TextEdit::singleline(&mut self.partner_id).hint_text("e.g. 123 456 789"));
            ui.add_space(6.0);

            ui.label("Password");
            ui.add(egui::TextEdit::singleline(&mut self.partner_password).password(true).hint_text("session password"));
            ui.add_space(12.0);

            let can_connect = !self.connecting && !self.partner_id.trim().is_empty();
            if ui.add_enabled(can_connect, egui::Button::new("🔗 Connect")).clicked() {
                self.start_connect();
            }
            if self.connecting {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Connecting…");
                });
            }
            if let Some(err) = &self.last_error {
                ui.colored_label(egui::Color32::from_rgb(210, 70, 70), err);
            }
        });
    }
}

impl eframe::App for InsDeskApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_session_result();

        if let Some(session) = &mut self.session {
            if !session.update(ctx) {
                self.session = None;
            }
        } else {
            self.home_ui(ctx);
        }

        ctx.request_repaint_after(std::time::Duration::from_millis(16));
    }
}

/// Format a 9-digit ID as "123 456 789" for readability.
fn group_digits(id: u64) -> String {
    let s = id.to_string();
    let mut out = String::new();
    let rem = s.len() % 3;
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (i.saturating_sub(rem)) % 3 == 0 {
            out.push(' ');
        }
        out.push(ch);
    }
    out
}

// ---------------------------------------------------------------------------
// The live session viewer
// ---------------------------------------------------------------------------

struct SessionView {
    commands: mpsc::Sender<ControllerCommand>,
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
    closed: bool,
}

impl SessionView {
    fn new(handle: ControllerHandle) -> Self {
        let _ = handle.commands.try_send(ControllerCommand::RequestKeyframe);
        let _ = handle.commands.try_send(ControllerCommand::Ping);
        SessionView {
            commands: handle.commands,
            events: handle.events,
            host_name: handle.host_name,
            host_id: handle.host_id,
            width: handle.width,
            height: handle.height,
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
            closed: false,
        }
    }

    fn send(&self, cmd: ControllerCommand) {
        let _ = self.commands.try_send(cmd);
    }

    /// Returns `false` when the session should close (back to the home screen).
    fn update(&mut self, ctx: &egui::Context) -> bool {
        self.drain_events(ctx);
        if self.closed {
            return false;
        }

        egui::TopBottomPanel::top("session_top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("⬅ Disconnect").clicked() {
                    self.send(ControllerCommand::Disconnect);
                    self.closed = true;
                }
                ui.separator();
                ui.strong(format!("{} ({})", self.host_name, group_digits(self.host_id)));
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

        egui::SidePanel::right("session_controls").default_width(260.0).show(ctx, |ui| {
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
                let response = ui.add(
                    egui::Image::new(egui::load::SizedTexture::new(tex.id(), size))
                        .sense(egui::Sense::click_and_drag()),
                );
                self.forward_input(ui, response.rect);
            } else {
                ui.centered_and_justified(|ui| ui.label("waiting for first frame…"));
            }
        });

        !self.closed
    }

    fn drain_events(&mut self, ctx: &egui::Context) {
        while let Ok(event) = self.events.try_recv() {
            match event {
                ControllerEvent::Frame { width, height, rgba, .. } => {
                    let image =
                        egui::ColorImage::from_rgba_unmultiplied([width as usize, height as usize], &rgba);
                    match &mut self.texture {
                        Some(tex) => tex.set(image, egui::TextureOptions::LINEAR),
                        None => {
                            self.texture =
                                Some(ctx.load_texture("remote", image, egui::TextureOptions::LINEAR))
                        }
                    }
                }
                ControllerEvent::Latency { millis } => self.latency_ms = Some(millis),
                ControllerEvent::SecureDesktop(active) => self.secure_desktop = active,
                ControllerEvent::DirListing { path, entries, error } => {
                    self.remote_path = path;
                    match error {
                        Some(e) => self.status = format!("ls error: {e}"),
                        None => self.listing = entries,
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
                    self.closed = true;
                }
                ControllerEvent::Error(e) => self.status = format!("error: {e}"),
                _ => {}
            }
        }
    }

    fn forward_input(&mut self, ui: &egui::Ui, image_rect: egui::Rect) {
        let input = ui.ctx().input(|i| i.clone());

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
