import tkinter as tk
from tkinter import ttk, messagebox
import math
import string
import secrets

AMBIGUOUS = set("Il1O0|`'\" ,.;:()[]{}<>")

UPPER = set(string.ascii_uppercase)
LOWER = set(string.ascii_lowercase)
DIGITS = set(string.digits)
SYMBOLS = set("!@#$%^&*_-+=?/~\\|:;.,()[]{}<>")

SYSTEM_RANDOM = secrets.SystemRandom()


def entropy_bits(length: int, pool_size: int) -> float:
    if length <= 0 or pool_size <= 1:
        return 0.0
    return length * math.log2(pool_size)


def classify_strength(bits: float) -> str:
    # Rough guidance based on NIST-ish heuristics
    if bits < 40:
        return "Weak"
    elif bits < 60:
        return "Fair"
    elif bits < 80:
        return "Strong"
    else:
        return "Excellent"


def has_no_long_repeats(pw: str, max_run: int = 2) -> bool:
    # Disallow runs like aaa (max_run=2) or 1111 (max_run=3), etc.
    if not pw:
        return True
    run = 1
    for i in range(1, len(pw)):
        if pw[i] == pw[i - 1]:
            run += 1
            if run > max_run:
                return False
        else:
            run = 1
    return True


def has_no_linear_sequences(pw: str, run_len: int = 3) -> bool:
    # Avoid obvious ascending/descending sequences like abc, 123, cba, 987
    if len(pw) < run_len:
        return True
    for i in range(len(pw) - run_len + 1):
        chunk = pw[i : i + run_len]
        diffs = [ord(chunk[j + 1]) - ord(chunk[j]) for j in range(len(chunk) - 1)]
        if all(d == 1 for d in diffs) or all(d == -1 for d in diffs):
            return False
    return True


def meets_category_requirements(pw: str, req_sets: list[set[str]]) -> bool:
    for s in req_sets:
        if not any(ch in s for ch in pw):
            return False
    return True


def build_pool(use_upper: bool, use_lower: bool, use_digits: bool, use_symbols: bool,
               exclude_chars: set[str], exclude_ambiguous: bool) -> tuple[list[str], list[set[str]]]:
    selected_sets = []
    if use_upper:
        selected_sets.append(UPPER)
    if use_lower:
        selected_sets.append(LOWER)
    if use_digits:
        selected_sets.append(DIGITS)
    if use_symbols:
        selected_sets.append(SYMBOLS)

    pool = set().union(*selected_sets) if selected_sets else set()

    if exclude_ambiguous:
        pool -= AMBIGUOUS
    if exclude_chars:
        pool -= exclude_chars

    # Remove whitespace just in case
    pool -= set(string.whitespace)

    return sorted(pool), selected_sets


def generate_password(
    length: int,
    use_upper: bool,
    use_lower: bool,
    use_digits: bool,
    use_symbols: bool,
    exclude_chars_text: str,
    exclude_ambiguous: bool,
    require_each_selected: bool = True,
    max_repeat_run: int = 2,
    avoid_sequences: bool = True,
    max_attempts: int = 5000,
) -> tuple[str, float, int]:
    """
    Returns: (password, entropy_bits, pool_size)
    Raises ValueError if inputs invalid or generation fails.
    """
    if length < 4 or length > 256:
        raise ValueError("Length must be between 4 and 256.")

    exclude_chars = set(exclude_chars_text) if exclude_chars_text else set()

    pool, selected_sets = build_pool(use_upper, use_lower, use_digits, use_symbols,
                                     exclude_chars, exclude_ambiguous)

    if not pool:
        raise ValueError("Character pool is empty. Adjust your selections/exclusions.")

    if require_each_selected and selected_sets and length < len(selected_sets):
        raise ValueError(
            f"Length too short to include one from each of the {len(selected_sets)} selected categories."
        )

    attempts = 0
    while attempts < max_attempts:
        attempts += 1

        chars = []
        # Ensure at least one from each selected set if requested
        if require_each_selected and selected_sets:
            for s in selected_sets:
                chars.append(SYSTEM_RANDOM.choice(list(s.intersection(pool))))

        # Fill the rest
        while len(chars) < length:
            chars.append(SYSTEM_RANDOM.choice(pool))

        # Shuffle for randomness
        SYSTEM_RANDOM.shuffle(chars)
        pw = ''.join(chars)

        if not has_no_long_repeats(pw, max_repeat_run):
            continue
        if avoid_sequences and not has_no_linear_sequences(pw, 3):
            continue
        if require_each_selected and selected_sets and not meets_category_requirements(pw, selected_sets):
            continue

        bits = entropy_bits(length, len(pool))
        return pw, bits, len(pool)

    raise ValueError("Unable to generate a password that meets all constraints. Try relaxing rules.")


class PasswordApp(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=12)
        self.master.title("Advanced Password Generator")
        self.master.geometry("760x520")
        self.master.minsize(720, 480)
        self.grid(sticky="nsew")

        for i in range(3):
            self.columnconfigure(i, weight=1)
        self.rowconfigure(3, weight=1)

        # Variables
        self.var_length = tk.IntVar(value=16)
        self.var_upper = tk.BooleanVar(value=True)
        self.var_lower = tk.BooleanVar(value=True)
        self.var_digits = tk.BooleanVar(value=True)
        self.var_symbols = tk.BooleanVar(value=True)
        self.var_exclude_amb = tk.BooleanVar(value=True)
        self.var_require_each = tk.BooleanVar(value=True)
        self.var_hide = tk.BooleanVar(value=False)
        self.var_max_run = tk.IntVar(value=2)
        self.var_avoid_sequences = tk.BooleanVar(value=True)
        self.var_count = tk.IntVar(value=1)

        # Header
        hdr = ttk.Label(self, text="Advanced Password Generator", font=("Segoe UI", 16, "bold"))
        hdr.grid(row=0, column=0, columnspan=3, sticky="w")

        # Length and count
        frm_len = ttk.Frame(self)
        frm_len.grid(row=1, column=0, sticky="ew", pady=(8, 4))
        frm_len.columnconfigure(3, weight=1)
        ttk.Label(frm_len, text="Length:").grid(row=0, column=0, sticky="w")
        self.spn_length = ttk.Spinbox(frm_len, from_=4, to=256, textvariable=self.var_length, width=6)
        self.spn_length.grid(row=0, column=1, sticky="w", padx=(6, 18))
        ttk.Label(frm_len, text="Count:").grid(row=0, column=2, sticky="w")
        self.spn_count = ttk.Spinbox(frm_len, from_=1, to=100, textvariable=self.var_count, width=6)
        self.spn_count.grid(row=0, column=3, sticky="w")

        # Character sets
        grp_sets = ttk.LabelFrame(self, text="Character Sets")
        grp_sets.grid(row=2, column=0, sticky="nsew", padx=(0, 8), pady=(4, 8))
        for i in range(2):
            grp_sets.columnconfigure(i, weight=1)
        ttk.Checkbutton(grp_sets, text="Uppercase (A-Z)", variable=self.var_upper).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(grp_sets, text="Lowercase (a-z)", variable=self.var_lower).grid(row=1, column=0, sticky="w")
        ttk.Checkbutton(grp_sets, text="Digits (0-9)", variable=self.var_digits).grid(row=0, column=1, sticky="w")
        ttk.Checkbutton(grp_sets, text="Symbols (!@#$…)", variable=self.var_symbols).grid(row=1, column=1, sticky="w")

        # Rules
        grp_rules = ttk.LabelFrame(self, text="Security Rules & Filters")
        grp_rules.grid(row=2, column=1, sticky="nsew", padx=(0, 8), pady=(4, 8))
        for i in range(2):
            grp_rules.columnconfigure(i, weight=1)
        ttk.Checkbutton(grp_rules, text="Require at least one of each selected set", variable=self.var_require_each).grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(grp_rules, text="Exclude ambiguous (I, l, 1, O, 0, …)", variable=self.var_exclude_amb).grid(row=1, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(grp_rules, text="Avoid linear sequences (abc, 123)", variable=self.var_avoid_sequences).grid(row=2, column=0, columnspan=2, sticky="w")
        ttk.Label(grp_rules, text="Max identical run:").grid(row=3, column=0, sticky="w")
        ttk.Spinbox(grp_rules, from_=1, to=10, textvariable=self.var_max_run, width=6).grid(row=3, column=1, sticky="w")
        ttk.Label(grp_rules, text="Exclude specific characters:").grid(row=4, column=0, sticky="w", pady=(6, 0))
        self.ent_exclude = ttk.Entry(grp_rules)
        self.ent_exclude.grid(row=4, column=1, sticky="ew", pady=(6, 0))

        # Output & actions
        grp_out = ttk.LabelFrame(self, text="Output")
        grp_out.grid(row=2, column=2, sticky="nsew", pady=(4, 8))
        grp_out.columnconfigure(0, weight=1)
        self.var_password = tk.StringVar()
        self.ent_password = ttk.Entry(grp_out, textvariable=self.var_password)
        self.ent_password.grid(row=0, column=0, sticky="ew", padx=6, pady=6)

        self.chk_hide = ttk.Checkbutton(grp_out, text="Hide", variable=self.var_hide, command=self.toggle_hide)
        self.chk_hide.grid(row=0, column=1, sticky="e", padx=(0, 6))

        self.lbl_strength = ttk.Label(grp_out, text="Entropy: 0.0 bits | Pool: 0 | Weak")
        self.lbl_strength.grid(row=1, column=0, columnspan=2, sticky="w", padx=6)

        btns = ttk.Frame(grp_out)
        btns.grid(row=2, column=0, columnspan=2, sticky="ew", padx=6, pady=6)
        btns.columnconfigure(0, weight=1)
        ttk.Button(btns, text="Generate", command=self.on_generate).grid(row=0, column=0, sticky="ew")
        ttk.Button(btns, text="Copy to Clipboard", command=self.copy_to_clipboard).grid(row=0, column=1, sticky="ew", padx=(6, 0))
        ttk.Button(btns, text="Clear", command=self.clear).grid(row=0, column=2, sticky="ew", padx=(6, 0))

        # Bulk list
        grp_list = ttk.LabelFrame(self, text="Generated Passwords (click to select)")
        grp_list.grid(row=3, column=0, columnspan=3, sticky="nsew", pady=(4, 0))
        grp_list.rowconfigure(0, weight=1)
        grp_list.columnconfigure(0, weight=1)
        self.lst_passwords = tk.Listbox(grp_list, height=8)
        self.lst_passwords.grid(row=0, column=0, sticky="nsew")
        self.lst_passwords.bind("<<ListboxSelect>>", self.on_select_from_list)
        sc = ttk.Scrollbar(grp_list, orient="vertical", command=self.lst_passwords.yview)
        sc.grid(row=0, column=1, sticky="ns")
        self.lst_passwords.configure(yscrollcommand=sc.set)

        # Status bar
        self.status = ttk.Label(self, text="Ready", anchor="w")
        self.status.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(6, 0))

        # Configure style for clarity
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        self.toggle_hide()

    def toggle_hide(self):
        self.ent_password.configure(show="•" if self.var_hide.get() else "")

    def on_generate(self):
        try:
            length = int(self.var_length.get())
            count = int(self.var_count.get())
            if count < 1 or count > 100:
                raise ValueError("Count must be between 1 and 100.")

            pwds = []
            # Build pool once to compute entropy consistently for display
            pool, _ = build_pool(
                self.var_upper.get(),
                self.var_lower.get(),
                self.var_digits.get(),
                self.var_symbols.get(),
                set(self.ent_exclude.get()),
                self.var_exclude_amb.get(),
            )
            if not pool:
                raise ValueError("Character pool is empty. Adjust your selections/exclusions.")

            for _ in range(count):
                pw, bits, pool_size = generate_password(
                    length,
                    self.var_upper.get(),
                    self.var_lower.get(),
                    self.var_digits.get(),
                    self.var_symbols.get(),
                    self.ent_exclude.get(),
                    self.var_exclude_amb.get(),
                    require_each_selected=self.var_require_each.get(),
                    max_repeat_run=int(self.var_max_run.get()),
                    avoid_sequences=self.var_avoid_sequences.get(),
                )
                pwds.append((pw, bits, pool_size))

            # Display last one in the entry + entropy label
            last_pw, bits, pool_size = pwds[-1]
            self.var_password.set(last_pw)
            self.lbl_strength.configure(text=f"Entropy: {bits:.1f} bits | Pool: {pool_size} | {classify_strength(bits)}")

            # Populate list
            self.lst_passwords.delete(0, tk.END)
            for pw, _, _ in pwds:
                self.lst_passwords.insert(tk.END, pw)

            self.status.configure(text=f"Generated {count} password(s).")
        except Exception as e:
            messagebox.showerror("Generation Error", str(e))
            self.status.configure(text="Error: " + str(e))

    def copy_to_clipboard(self):
        pw = self.var_password.get()
        if not pw:
            messagebox.showinfo("Copy", "No password to copy.")
            return
        try:
            self.master.clipboard_clear()
            self.master.clipboard_append(pw)
            self.master.update()  # Ensures it stays on the clipboard
            self.status.configure(text="Password copied to clipboard.")
        except Exception as e:
            messagebox.showerror("Clipboard Error", str(e))

    def on_select_from_list(self, event):
        sel = self.lst_passwords.curselection()
        if not sel:
            return
        pw = self.lst_passwords.get(sel[0])
        self.var_password.set(pw)

    def clear(self):
        self.var_password.set("")
        self.lst_passwords.delete(0, tk.END)
        self.lbl_strength.configure(text="Entropy: 0.0 bits | Pool: 0 | Weak")
        self.status.configure(text="Cleared.")


def main():
    root = tk.Tk()
    root.rowconfigure(0, weight=1)
    root.columnconfigure(0, weight=1)
    app = PasswordApp(root)
    app.grid(sticky="nsew")
    root.mainloop()


if __name__ == "__main__":
    main()
