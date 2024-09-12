import tkinter as tk
from tkinter import messagebox

class PasswordApp:
    def __init__(self, root):  # Corrected method name
        self.root = root
        self.root.title("Password Verification")
        self.correct_password = ""

        # Set password widgets
        self.set_password_label = tk.Label(root, text="Set your password:")
        self.set_password_label.grid(row=0, column=0, padx=10, pady=10)

        self.set_password_entry = tk.Entry(root, show='*')
        self.set_password_entry.grid(row=0, column=1, padx=10, pady=10)

        self.show_set_password_var = tk.IntVar()
        self.show_set_password_check = tk.Checkbutton(root, text="Show", variable=self.show_set_password_var, command=self.toggle_set_password_visibility)
        self.show_set_password_check.grid(row=0, column=2, padx=10, pady=10)

        self.set_password_button = tk.Button(root, text="Set Password", command=self.set_password)
        self.set_password_button.grid(row=1, column=1, padx=10, pady=10)

        # Verify password widgets
        self.verify_password_label = tk.Label(root, text="Enter the password again:")
        self.verify_password_label.grid(row=2, column=0, padx=10, pady=10)

        self.verify_password_entry = tk.Entry(root, show='*')
        self.verify_password_entry.grid(row=2, column=1, padx=10, pady=10)

        self.show_verify_password_var = tk.IntVar()
        self.show_verify_password_check = tk.Checkbutton(root, text="Show", variable=self.show_verify_password_var, command=self.toggle_verify_password_visibility)
        self.show_verify_password_check.grid(row=2, column=2, padx=10, pady=10)

        self.login_button = tk.Button(root, text="Login", command=self.check_password)
        self.login_button.grid(row=3, column=1, padx=10, pady=10)

        self.status_label = tk.Label(root, text="")
        self.status_label.grid(row=4, column=0, columnspan=3, padx=10, pady=10)

    def toggle_set_password_visibility(self):
        if self.show_set_password_var.get():
            self.set_password_entry.config(show='')
        else:
            self.set_password_entry.config(show='*')

    def toggle_verify_password_visibility(self):
        if self.show_verify_password_var.get():
            self.verify_password_entry.config(show='')
        else:
            self.verify_password_entry.config(show='*')

    def set_password(self):
        self.correct_password = self.set_password_entry.get()
        self.set_password_entry.delete(0, tk.END)
        self.status_label.config(text="Password set!")

    def check_password(self):
        entered_password = self.verify_password_entry.get()
        self.verify_password_entry.delete(0, tk.END)
        if entered_password == self.correct_password:
            messagebox.showinfo("Success", "Login Successful!")
            self.status_label.config(text="Login Successful!")
        else:
            messagebox.showerror("Error", "Incorrect password, try again.")
            self.status_label.config(text="Incorrect password, try again.")

if __name__ == "__main__":  # Corrected condition
    root = tk.Tk()
    app = PasswordApp(root)
    root.mainloop()
