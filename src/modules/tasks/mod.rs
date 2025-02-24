pub mod model;
mod progress;
mod storage;
pub mod user_interface;

pub use model::Task;
pub use progress::handle_interactive_progress_update;
pub use storage::{load_tasks_from_file, save_tasks_to_file, TaskError};
pub use user_interface::{
    handle_add_command, handle_delete_command, handle_edit_command,
    handle_interactive_task_creation, handle_interactive_task_edit, handle_list_command,
    handle_progress_command,
};
