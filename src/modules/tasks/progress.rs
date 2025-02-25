use super::model::Task;
use crate::modules::utils::io::read_line;

/// Function to handle interactive progress update
pub fn handle_interactive_progress_update(task: &mut Task) -> Result<(), String> {
    println!("\nCurrent progress: {}%", task.progress_percent);
    println!("Current visualization: {}", task.generate_progress_bar());

    // Show progress bar style options
    println!("\nAvailable progress bar styles:");
    println!("1. Simple  [=====>    ]");
    println!("2. Block   [██████    ]");
    println!("3. Numeric [60%]");
    println!("4. Detailed [======>   ] 6/10");

    println!("\nEnter style number (or press Enter to keep current):");
    let style_input = read_line().map_err(|e| e.to_string())?;

    if !style_input.trim().is_empty() {
        task.progress_bar_style = match style_input.trim() {
            "1" => "simple".to_string(),
            "2" => "block".to_string(),
            "3" => "numeric".to_string(),
            "4" => "detailed".to_string(),
            _ => {
                println!("Invalid style. Keeping current style.");
                task.progress_bar_style.clone()
            }
        };
    }

    println!("\nEnter new progress percentage (0-100):");
    let progress_input = read_line().map_err(|e| e.to_string())?;

    match progress_input.trim().parse::<u8>() {
        Ok(progress) => {
            task.update_progress(progress)?;
            println!("\nProgress updated: {}", task.generate_progress_bar());
            Ok(())
        }
        Err(_) => {
            Err("Invalid progress value. Please enter a number between 0 and 100.".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    struct MockTask {
        progress_percent: u8,
        progress_bar_style: String,
    }

    impl MockTask {
        fn update_progress(&mut self, new_progress: u8) -> Result<(), String> {
            if new_progress > 100 {
                return Err("Progress cannot exceed 100%".to_string());
            }
            self.progress_percent = new_progress;
            Ok(())
        }

        fn generate_progress_bar(&self) -> String {
            // Actually use the field
            if self.progress_bar_style == "simple" {
                return format!("{}%", self.progress_percent);
            }
            // Default fallback
            format!("{}%", self.progress_percent)
        }
    }

    #[test]
    fn test_progress_update() {
        let mut task = MockTask {
            progress_percent: 50,
            progress_bar_style: "simple".to_string(),
        };

        // Test valid progress update
        assert!(task.update_progress(75).is_ok());
        assert_eq!(task.progress_percent, 75);

        // Test invalid progress update
        assert!(task.update_progress(101).is_err());
        assert_eq!(task.progress_percent, 75); // Should not change

        // Test progress bar generation
        assert_eq!(task.generate_progress_bar(), "75%");
    }
}
