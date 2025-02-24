use serde::{Deserialize, Serialize};

/// Structure representing a single task that includes progress tracking
#[derive(Serialize, Deserialize, Debug)]
pub struct Task {
    pub name: String,
    pub description: String,
    pub priority: String,
    pub completed: bool,
    pub progress_percent: u8,       // Stores progress as 0-100
    pub progress_bar_style: String, // Stores the chosen style for progress visualization
}

impl Task {
    /// Add method to update progress
    pub fn update_progress(&mut self, new_progress: u8) -> Result<(), String> {
        // Validate progress value
        if new_progress > 100 {
            return Err("Progress cannot exceed 100%".to_string());
        }

        self.progress_percent = new_progress;

        // Automatically set completed flag when progress reaches 100%
        self.completed = new_progress == 100;

        Ok(())
    }

    /// Method to generate ASCII progress bar based on chosen style
    pub fn generate_progress_bar(&self) -> String {
        match self.progress_bar_style.as_str() {
            "simple" => {
                // Generate [=====>    ] style progress bar
                let filled = (self.progress_percent as f32 / 10.0).round() as usize;
                let empty = 10 - filled;
                let bar = "=".repeat(filled.max(0));
                let spaces = " ".repeat(empty.max(0));
                format!("[{}>{spaces}] {}%", bar, self.progress_percent)
            }
            "block" => {
                // Generate [██████    ] style progress bar using block characters
                let filled = (self.progress_percent as f32 / 10.0).round() as usize;
                let empty = 10 - filled;
                let bar = "█".repeat(filled.max(0));
                let spaces = " ".repeat(empty.max(0));
                format!("[{bar}{spaces}] {}%", self.progress_percent)
            }
            "numeric" => {
                // Simple numeric display
                format!("[{}%]", self.progress_percent)
            }
            "detailed" => {
                // Detailed progress bar with fraction
                let filled = (self.progress_percent as f32 / 10.0).round() as usize;
                let empty = 10 - filled;
                let bar = "=".repeat(filled.max(0));
                let spaces = " ".repeat(empty.max(0));
                format!("[{bar}>{spaces}] {}/10", filled)
            }
            _ => format!("{}%", self.progress_percent), // Default fallback
        }
    }
}

/// Available progress bar styles
#[derive(Serialize, Deserialize, Debug)]
pub enum ProgressBarStyle {
    Simple,   // [=====>    ] style
    Block,    // [██████    ] style
    Numeric,  // [60%] style
    Detailed, // [======>   ] 6/10 style
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_task_auto_completion() {
        // Create a test task with progress below 100%
        let mut task = Task {
            name: "Test Task".to_string(),
            description: "Test Description".to_string(),
            priority: "High".to_string(),
            completed: false,
            progress_percent: 99,
            progress_bar_style: "simple".to_string(),
        };

        // Test that task is not completed initially
        assert!(!task.completed);
        assert_eq!(task.progress_percent, 99);

        // Update progress to 100% - should auto-complete
        task.update_progress(100).unwrap();
        assert!(task.completed);
        assert_eq!(task.progress_percent, 100);

        // Test that progress can't exceed 100%
        assert!(task.update_progress(101).is_err());

        // Create already completed task
        let mut completed_task = Task {
            name: "Completed Task".to_string(),
            description: "Test Description".to_string(),
            priority: "High".to_string(),
            completed: true,
            progress_percent: 100,
            progress_bar_style: "simple".to_string(),
        };

        // Test completed task
        assert!(completed_task.completed);
        assert_eq!(completed_task.progress_percent, 100);

        // When progress is updated to less than 100%, completed status should be false
        completed_task.update_progress(50).unwrap();
        assert!(!completed_task.completed);
        assert_eq!(completed_task.progress_percent, 50);
    }

    #[test]
    fn test_progress_bar_styles() {
        let mut task = Task {
            name: "Style Test".to_string(),
            description: "Testing progress bar styles".to_string(),
            priority: "Medium".to_string(),
            completed: false,
            progress_percent: 60,
            progress_bar_style: "simple".to_string(),
        };

        // Test simple style
        assert!(task.generate_progress_bar().contains("======>"));
        assert!(task.generate_progress_bar().contains("60%"));

        // Test block style
        task.progress_bar_style = "block".to_string();
        assert!(task.generate_progress_bar().contains("██████"));

        // Test numeric style
        task.progress_bar_style = "numeric".to_string();
        assert_eq!(task.generate_progress_bar(), "[60%]");

        // Test detailed style
        task.progress_bar_style = "detailed".to_string();
        assert!(task.generate_progress_bar().contains("6/10"));

        // Test unknown style
        task.progress_bar_style = "unknown".to_string();
        assert_eq!(task.generate_progress_bar(), "60%");
    }
}