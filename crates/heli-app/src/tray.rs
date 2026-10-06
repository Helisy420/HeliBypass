//! System tray icon. Clicks open a custom popup window (see `ui/tray.slint`), positioned by
//! the main module from the cursor location.

use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

#[derive(Clone, Copy, Debug)]
pub enum TrayAction {
    /// Show or hide the popup.
    Popup,
    /// Open the main window.
    Open,
}

pub struct Tray {
    icon: TrayIcon,
    active: Option<bool>,
}

fn icon(active: bool) -> Option<Icon> {
    let rgba = crate::logo::render(32, false, active);
    Icon::from_rgba(rgba, 32, 32).ok()
}

impl Tray {
    /// `handler` runs on a tray-owned thread; hop to the UI thread inside it.
    pub fn create(handler: impl Fn(TrayAction) + Send + Sync + 'static) -> Option<Self> {
        TrayIconEvent::set_event_handler(Some(move |ev: TrayIconEvent| match ev {
            TrayIconEvent::Click { button: MouseButton::Left | MouseButton::Right, button_state: MouseButtonState::Up, .. } => {
                handler(TrayAction::Popup)
            }
            TrayIconEvent::DoubleClick { button: MouseButton::Left, .. } => handler(TrayAction::Open),
            _ => {}
        }));
        let built = TrayIconBuilder::new().with_icon(icon(true)?).with_tooltip("Heli Bypass").build().ok()?;
        Some(Self { icon: built, active: Some(true) })
    }

    pub fn update(&mut self, protected: bool, tooltip: &str) {
        if self.active != Some(protected) {
            if let Some(i) = icon(protected) {
                let _ = self.icon.set_icon(Some(i));
                self.active = Some(protected);
            }
        }
        let _ = self.icon.set_tooltip(Some(tooltip));
    }
}
