// The desktop entry point. Everything lives in the library so that the same code can be built for
// other targets; `windows_subsystem` keeps a console from appearing behind the window on Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    myna_sign_app_lib::run()
}
