// A GUI app in every build profile: the console subsystem would open a cmd window next to it.
// Logs go to the data folder (see `logging.rs`), not to stdout.
#![windows_subsystem = "windows"]

mod backend;
mod bridge;
#[cfg(debug_assertions)]
mod demo;
mod i18n;
mod logging;
#[allow(dead_code)]
mod logo;
mod platform;
mod speed;
mod tray;

slint::include_modules!();

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use backend::Backend;
use heli_core::paths::Paths;
use slint::{CloseRequestResponse, ComponentHandle, Image, PhysicalPosition, Rgba8Pixel, SharedPixelBuffer, Timer, TimerMode};

fn icon_image(size: u32, tile: bool) -> Image {
    let rgba = logo::render(size, tile, true);
    let buf = SharedPixelBuffer::<Rgba8Pixel>::clone_from_slice(&rgba, size, size);
    Image::from_rgba8(buf)
}

/// UI-thread state shared by the timers and callbacks.
struct Ctx {
    main: MainWindow,
    popup: TrayMenu,
    backend: Arc<Backend>,
    prev: RefCell<Option<bridge::View>>,
    last_page: Cell<i32>,
    popup_shown_at: Cell<Option<Instant>>,
    tray: RefCell<Option<tray::Tray>>,
    demo: bool,
}

thread_local! {
    static CTX: RefCell<Option<Rc<Ctx>>> = const { RefCell::new(None) };
}

fn ctx() -> Option<Rc<Ctx>> {
    CTX.with(|c| c.borrow().clone())
}

impl Ctx {
    fn sync(&self) {
        if self.demo {
            return;
        }
        let view = bridge::build_view(&self.backend);
        {
            let prev = self.prev.borrow();
            if prev.as_ref() == Some(&view) {
                return;
            }
            bridge::apply(&self.main.global::<AppState>(), &view, prev.as_ref());
            bridge::apply(&self.popup.global::<AppState>(), &view, prev.as_ref());
        }
        if let Some(t) = self.tray.borrow_mut().as_mut() {
            let tip = if view.protected { format!("Heli Bypass — {}", i18n::tr("Protected")) } else { format!("Heli Bypass — {}", i18n::tr("Not protected")) };
            t.update(view.protected, &tip);
        }
        *self.prev.borrow_mut() = Some(view);
    }

    fn show_main(&self) {
        let _ = self.main.show();
        self.main.window().set_minimized(false);
        self.backend.visible.store(true, Ordering::Relaxed);
        if let Some(h) = platform::hwnd_of(self.main.window()) {
            platform::style_window(h);
            platform::focus_window(h);
        }
        self.sync();
    }

    fn hide_popup(&self) {
        let _ = self.popup.hide();
        self.popup_shown_at.set(None);
    }

    fn toggle_popup(&self) {
        if self.popup_shown_at.get().is_some() {
            return self.hide_popup();
        }
        self.sync();
        let cursor = platform::cursor_position();
        let (l, t, r, b) = platform::work_area_at(cursor);
        let scale = self.popup.window().scale_factor();
        let (w, h) = ((self.popup.get_panel_width() * scale) as i32, (self.popup.get_panel_height() * scale) as i32);
        let x = (cursor.0 - w / 2).clamp(l + 8, (r - w - 8).max(l + 8));
        let y = (cursor.1 - h - 12).clamp(t + 8, (b - h - 8).max(t + 8));
        self.popup.window().set_position(PhysicalPosition::new(x, y));
        let _ = self.popup.show();
        if let Some(hwnd) = platform::hwnd_of(self.popup.window()) {
            platform::style_window(hwnd);
            platform::focus_window(hwnd);
        }
        self.popup_shown_at.set(Some(Instant::now()));
    }

    fn quit(&self) {
        let backend = Arc::clone(&self.backend);
        backend.rt.block_on(backend.shutdown());
        let _ = slint::quit_event_loop();
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let flag = |f: &str| args.iter().any(|a| a == f);
    let value = |f: &str| args.iter().skip_while(|a| *a != f).nth(1).cloned();
    let demo = cfg!(debug_assertions) && flag("--demo");

    // demo mode (debug builds) may run next to a real instance, for screenshots
    let instance = match platform::SingleInstance::acquire() {
        Some(i) => Some(i),
        None if demo => None,
        None => return,
    };

    let paths = Paths::default_location().clone();
    let _ = paths.ensure_dirs();
    let verbose = heli_core::config::AppConfig::load(&paths.config_file()).app.verbose_logs;
    logging::init(paths.logs_dir(), verbose);
    tracing::info!("HeliBypass {} starting (data in {})", env!("CARGO_PKG_VERSION"), paths.root().display());

    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).thread_name("heli-rt").enable_all().build().expect("tokio runtime");

    let pending = Arc::new(AtomicBool::new(false));
    let wake: Arc<dyn Fn() + Send + Sync> = {
        let pending = Arc::clone(&pending);
        Arc::new(move || {
            if !pending.swap(true, Ordering::AcqRel) {
                let pending = Arc::clone(&pending);
                let _ = slint::invoke_from_event_loop(move || {
                    pending.store(false, Ordering::Release);
                    if let Some(c) = ctx() {
                        c.sync();
                    }
                });
            }
        })
    };
    let backend = Backend::new(rt.handle().clone(), paths.clone(), Arc::clone(&wake));

    let main = MainWindow::new().expect("main window");
    let popup = TrayMenu::new().expect("tray popup");
    let lang = i18n::language();
    if lang == i18n::Language::Russian {
        let _ = slint::select_bundled_translation("ru");
    }
    let app_icon = icon_image(64, true);
    main.set_app_icon(app_icon.clone());
    popup.set_app_icon(app_icon);

    bridge::wire_main(&main, &backend);
    bridge::wire_common(&popup.global::<AppState>(), &backend);
    bridge::load_forms(&main.global::<AppState>(), &backend);
    bridge::load_settings(&main.global::<AppState>(), &backend);
    main.global::<AppState>().set_version(format!("v{}", env!("CARGO_PKG_VERSION")).into());
    popup.global::<AppState>().set_version(format!("v{}", env!("CARGO_PKG_VERSION")).into());

    let ctx_rc = Rc::new(Ctx {
        main,
        popup,
        backend: Arc::clone(&backend),
        prev: RefCell::new(None),
        last_page: Cell::new(-1),
        popup_shown_at: Cell::new(None),
        tray: RefCell::new(None),
        demo,
    });
    CTX.with(|c| *c.borrow_mut() = Some(Rc::clone(&ctx_rc)));

    // window controls
    {
        let c = Rc::downgrade(&ctx_rc);
        ctx_rc.main.on_minimize({
            let c = c.clone();
            move || {
                if let Some(c) = c.upgrade() {
                    c.main.window().set_minimized(true);
                }
            }
        });
        ctx_rc.main.on_toggle_maximize({
            let c = c.clone();
            move || {
                if let Some(c) = c.upgrade() {
                    let w = c.main.window();
                    w.set_maximized(!w.is_maximized());
                }
            }
        });
        let close = {
            let c = c.clone();
            move || {
                if let Some(c) = c.upgrade() {
                    let to_tray = c.backend.cfg.lock().unwrap_or_else(|e| e.into_inner()).app.close_to_tray && c.tray.borrow().is_some();
                    if to_tray {
                        let _ = c.main.hide();
                        c.backend.visible.store(false, Ordering::Relaxed);
                    } else {
                        c.quit();
                    }
                }
            }
        };
        ctx_rc.main.on_close_window(close.clone());
        ctx_rc.main.window().on_close_requested({
            let close = close.clone();
            move || {
                close();
                CloseRequestResponse::KeepWindowShown
            }
        });
        ctx_rc.popup.on_open_app({
            let c = c.clone();
            move || {
                if let Some(c) = c.upgrade() {
                    c.hide_popup();
                    c.show_main();
                }
            }
        });
        ctx_rc.popup.on_quit({
            let c = c.clone();
            move || {
                if let Some(c) = c.upgrade() {
                    c.quit();
                }
            }
        });
    }

    // tray
    {
        let tray = tray::Tray::create(|action| {
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(c) = ctx() {
                    match action {
                        tray::TrayAction::Popup => c.toggle_popup(),
                        tray::TrayAction::Open => {
                            c.hide_popup();
                            c.show_main();
                        }
                    }
                }
            });
        });
        if tray.is_none() {
            tracing::warn!("could not create the tray icon");
        }
        *ctx_rc.tray.borrow_mut() = tray;
    }

    // a second launch asks this instance to show its window
    if let Some(instance) = &instance {
        instance.watch(|| {
            let _ = slint::invoke_from_event_loop(|| {
                if let Some(c) = ctx() {
                    c.show_main();
                }
            });
        });
    }

    if demo {
        #[cfg(debug_assertions)]
        {
            let s = ctx_rc.main.global::<AppState>();
            demo::apply(&s);
            s.set_page(value("--page").and_then(|p| p.parse().ok()).unwrap_or(0));
            if let Some((w, h)) = value("--size").and_then(|v| v.split_once('x').map(|(a, b)| (a.parse::<f32>().ok(), b.parse::<f32>().ok()))).and_then(|(a, b)| Some((a?, b?))) {
                ctx_rc.main.window().set_size(slint::LogicalSize::new(w, h));
            }
            if flag("--studio") {
                s.set_build_base("general (ALT13)".into());
                s.set_smart_running(true);
                s.set_test_label("Stage 2 of 3: refining · #21 · fake,multisplit · ts · pos 2 · seqovl 681 · ×6".into());
                s.set_build_note("Saved as customhelibypass · fake,multisplit · ts · seqovl 681 · ×7".into());
                s.invoke_studio_load();
            }
            if let Some(l) = value("--lang") {
                let _ = slint::select_bundled_translation(&l);
            }
        }
    }

    // fast timer: page changes, popup focus, minimised state; every 5th tick a full refresh
    let ticks = Cell::new(0u32);
    let timer = Timer::default();
    {
        let weak = Rc::downgrade(&ctx_rc);
        timer.start(TimerMode::Repeated, Duration::from_millis(200), move || {
            let Some(c) = weak.upgrade() else { return };
            ticks.set(ticks.get().wrapping_add(1));
            let visible = c.main.window().is_visible() && !c.main.window().is_minimized();
            c.backend.visible.store(visible, Ordering::Relaxed);
            if let Some(shown) = c.popup_shown_at.get() {
                let me = platform::hwnd_of(c.popup.window());
                if !c.demo && shown.elapsed() > Duration::from_millis(500) && me.is_some_and(|h| platform::foreground_window() != h) {
                    c.hide_popup();
                }
            }
            if !c.demo {
                let page = c.main.global::<AppState>().get_page();
                if page != c.last_page.get() {
                    c.last_page.set(page);
                    bridge::on_page_changed(&c.backend, &c.main, page);
                }
                if visible && ticks.get() % 5 == 0 {
                    c.sync();
                } else if !visible && ticks.get() % 25 == 0 {
                    c.sync(); // keeps the tray icon/tooltip current while hidden
                }
            }
        });
    }

    let start_hidden = !demo && (flag("--minimized") || backend.cfg.lock().unwrap_or_else(|e| e.into_inner()).app.start_minimized) && ctx_rc.tray.borrow().is_some();
    if !demo {
        backend.start_background();
    }
    if demo && flag("--popup") {
        ctx_rc.toggle_popup();
    } else if !start_hidden {
        ctx_rc.show_main();
    } else {
        backend.visible.store(false, Ordering::Relaxed);
    }
    ctx_rc.sync();
    #[cfg(debug_assertions)]
    if demo && flag("--clickthrough") {
        if let Some(h) = platform::hwnd_of(ctx_rc.main.window()) {
            platform::make_click_through(h);
        }
    }

    let _ = slint::run_event_loop_until_quit();

    tracing::info!("HeliBypass exiting");
    rt.block_on(backend.shutdown());
    CTX.with(|c| *c.borrow_mut() = None);
    drop(timer);
}
