use std::io::Write;

/// Prompts the user with a question and expects a response indicating confirmation.
///
/// This function displays a specified prompt message to the standard output and waits
/// for the user to input a response. It assesses the response to check whether it
/// indicates agreement (e.g., "y", "Y", "yes", "YES", "Yes") and returns a corresponding
/// boolean value (`true` for agreement, `false` otherwise). Optionally, an abort message
/// can be displayed if the user does not confirm.
///
/// # Arguments
///
/// * `prompt` - A `String` containing the message to be displayed to the user.
/// * `abort_message` - An `Option<String>` containing a message to display if the user
///   does not confirm. If `None` or an empty string is provided, no abort message is displayed.
///
/// # Returns
///
/// * `true` - If the user provides a response indicating agreement (e.g., "y", "Y", "yes").
/// * `false` - If the user provides a response not indicating agreement, or otherwise.
///
/// # Panics
///
/// This function will panic if there is an error while:
/// - Flushing the standard output.
/// - Reading a line from the standard input.
///
/// # Examples
///
/// ```
/// use my_crate::ask_response;
///
/// let prompt = "Do you want to proceed? (y/n): ".to_string();
/// let abort_message = Some("Operation aborted by the user.".to_string());
///
/// if ask_response(prompt, abort_message) {
///     println!("User confirmed!");
/// } else {
///     println!("User did not confirm.");
/// }
/// ```
///
/// In the above example:
/// 1. If the user types "y" or "yes" (case-insensitive), `ask_response` returns `true`.
/// 2. If the user types anything else, `ask_response` prints the `abort_message`
///    (if provided) and returns `false`.
///
pub fn ask_response(prompt: String, abort_message: Option<String>) -> bool {
    print!("{}", prompt);
    std::io::stdout().flush().unwrap();
    let mut response = String::new();
    std::io::stdin().read_line(&mut response).unwrap();

    if !["y", "Y", "yes", "YES", "Yes"].contains(&response.trim()) {
        let abort_message = abort_message.unwrap_or_default();
        if !abort_message.is_empty() {
            println!("{}", abort_message);
        }

        return false;
    }

    true
}
