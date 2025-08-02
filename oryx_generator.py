import os
import json
import csv
import random
import tkinter as tk
import traceback # Added for detailed error tracking
from datetime import datetime
from tkinter import filedialog, ttk, messagebox
from eth_account import Account
from solana.keypair import Keypair as SolanaKeypair
from mnemonic import Mnemonic
from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
import base58

# Enable HD Wallet features for Ethereum accounts
Account.enable_unaudited_hdwallet_features()

# --- Core Logic Functions ---

def sanitize_filename(name):
    """Removes spaces and special characters from a string to make it a valid filename."""
    return name.replace(" ", "_").replace("+", "").lower()

def generate_evm_wallet(output_type):
    """Generates an EVM-compatible wallet (e.g., Ethereum, BSC)."""
    mnemonic = Account.create_with_mnemonic()[1]
    acct = Account.from_mnemonic(mnemonic)
    data = {"address": acct.address}
    if "Seed" in output_type:
        data["seed_phrase"] = mnemonic
    if "Private" in output_type:
        data["private_key"] = "0x" + acct.key.hex()
    return data

def generate_solana_wallet(output_type):
    """
    Generates a Solana wallet directly from a random private key.
    This method does not use a seed phrase to avoid derivation path issues.
    """
    # 1. Generate a new random keypair.
    kp = SolanaKeypair()

    # 2. Extract address and private key
    pubkey = str(kp.public_key)
    privkey = base58.b58encode(kp.secret_key).decode()
    
    data = {"address": pubkey}
    
    # For Solana, we now only support private key generation.
    # The "seed_phrase" key will be intentionally omitted even if requested.
    if "Private" in output_type:
        data["private_key"] = privkey
        
    return data

def generate_cosmos_wallet(output_type):
    """Generates a Cosmos (ATOM) wallet."""
    mnemonic = Bip39MnemonicGenerator().FromWordsNumber(12)
    seed_bytes = Bip39SeedGenerator(str(mnemonic)).Generate()
    # Derivation path for Cosmos: m/44'/118'/0'/0/0
    acct = Bip44.FromSeed(seed_bytes, Bip44Coins.COSMOS).Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
    address = acct.PublicKey().ToAddress()
    privkey = acct.PrivateKey().Raw().ToHex()
    data = {"address": address}
    if "Seed" in output_type:
        data["seed_phrase"] = str(mnemonic)
    if "Private" in output_type:
        data["private_key"] = "0x" + privkey
    return data

def save_wallets_to_file(wallets, output_format, output_path, network, output_type):
    """Saves the generated wallet data to a file in the specified format."""
    output_dir = os.path.join(output_path, network)
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename_base = sanitize_filename(output_type)
    filename = f"{filename_base}_{timestamp}.{output_format.lower()}"
    full_path = os.path.join(output_dir, filename)

    if output_format == "TXT":
        with open(full_path, "w", encoding='utf-8') as f:
            for wallet in wallets:
                f.write(json.dumps(wallet) + "\n")
    elif output_format == "CSV":
        if not wallets: return
        # Ensure all wallets have the same keys for CSV
        # Take keys from the first wallet as header
        all_keys = []
        if wallets:
            all_keys = list(wallets[0].keys())
            # Ensure all keys are in the header
            for w in wallets:
                for k in w.keys():
                    if k not in all_keys:
                        all_keys.append(k)

        with open(full_path, "w", newline="", encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=all_keys)
            writer.writeheader()
            writer.writerows(wallets)
    elif output_format == "JSON":
        with open(full_path, "w", encoding='utf-8') as f:
            json.dump(wallets, f, indent=4)

    return full_path


# --- GUI Application Class (Visually Updated) ---
class WalletGeneratorApp:
    def __init__(self, master):
        self.master = master
        master.title("Oryx Generator")
        master.geometry("550x680")
        master.resizable(False, False)

        # --- Load .ico file for the window icon ---
        icon_path = "./icon/favicon.ico"
        if os.path.exists(icon_path):
            try:
                # Use iconbitmap for .ico files, the standard and most reliable method
                master.iconbitmap(icon_path)
            except tk.TclError as e:
                print(f"Could not load icon from {icon_path}: {e}")
        else:
            print(f"Icon file not found at: {icon_path}. Skipping icon.")


        self.setup_styles()
        
        main_frame = ttk.Frame(master, style='Main.TFrame')
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.create_widgets(main_frame)

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        BG_COLOR, FG_COLOR, FRAME_BG, ACCENT_COLOR, BUTTON_COLOR, BUTTON_HOVER = "#2E3440", "#ECEFF4", "#3B4252", "#88C0D0", "#5E81AC", "#81A1C1"
        self.style.configure('.', background=BG_COLOR, foreground=FG_COLOR, font=('Segoe UI', 10))
        self.style.configure('Main.TFrame', background=BG_COLOR)
        self.style.configure('TLabel', background=BG_COLOR, foreground=FG_COLOR)
        self.style.configure('Title.TLabel', font=('Segoe UI', 20, 'bold'), foreground=ACCENT_COLOR)
        self.style.configure('TLabelFrame', background=FRAME_BG, bordercolor=ACCENT_COLOR)
        self.style.configure('TLabelFrame.Label', background=FRAME_BG, foreground=FG_COLOR, font=('Segoe UI', 11, 'bold'))
        self.style.configure('TRadiobutton', background=FRAME_BG, foreground=FG_COLOR)
        self.style.map('TRadiobutton', background=[('active', FRAME_BG)], indicatorcolor=[('selected', ACCENT_COLOR), ('!selected', FG_COLOR)])
        self.style.configure('TCombobox', fieldbackground=FRAME_BG, background=BUTTON_COLOR, foreground=FG_COLOR, arrowcolor=FG_COLOR, bordercolor=ACCENT_COLOR, selectbackground=BUTTON_COLOR, selectforeground=FG_COLOR)
        self.style.map('TCombobox', fieldbackground=[('readonly', FRAME_BG)])
        self.style.configure('TEntry', fieldbackground=FRAME_BG, foreground=FG_COLOR, insertcolor=FG_COLOR)
        self.style.configure('TSpinbox', fieldbackground=FRAME_BG, foreground=FG_COLOR, insertcolor=FG_COLOR, arrowsize=15)
        self.style.map('TSpinbox', background=[('active', BUTTON_COLOR)])
        self.style.configure('TButton', font=('Segoe UI', 12, 'bold'), background=BUTTON_COLOR, foreground=FG_COLOR, borderwidth=0, focusthickness=0, padding=10)
        self.style.map('TButton', background=[('active', BUTTON_HOVER), ('!disabled', BUTTON_COLOR)], foreground=[('active', FG_COLOR)])

    def update_output_options(self, *args):
        """Updates the output data dropdown based on the selected network."""
        network = self.network_var.get()
        
        # Define options for different networks
        evm_cosmos_options = ["Address + Seed", "Address + Private", "Address + Seed + Private", "Address + Amount"]
        solana_options = ["Address + Private", "Address + Amount"]
        
        if network == "Solana":
            self.output_type_dropdown['values'] = solana_options
            # If the current selection is not in the new list, set it to the default
            if self.output_type_var.get() not in solana_options:
                self.output_type_var.set("Address + Private")
        else: # For EVM and Cosmos
            self.output_type_dropdown['values'] = evm_cosmos_options
            # If the current selection is not in the new list, set it to the default
            if self.output_type_var.get() not in evm_cosmos_options:
                self.output_type_var.set("Address + Seed + Private")
        
        # Call toggle_amount_input to ensure its visibility is correct
        self.toggle_amount_input()

    def create_widgets(self, parent):
        # The logo is no longer displayed inside the main window
        ttk.Label(parent, text="Oryx Generator", style='Title.TLabel').pack(pady=(10, 10))
        
        frame_net = ttk.LabelFrame(parent, text="Select Network")
        frame_net.pack(padx=10, pady=10, fill="x")
        self.network_var = tk.StringVar(value="EVM")
        # Add a trace to call the update function when the network changes
        self.network_var.trace("w", self.update_output_options)

        for net in ["EVM", "Solana", "Cosmos"]:
            ttk.Radiobutton(frame_net, text=net, variable=self.network_var, value=net).pack(anchor="w", padx=10, pady=2)
        
        self.frame_output_type = ttk.LabelFrame(parent, text="Output Data")
        self.frame_output_type.pack(padx=10, pady=10, fill="x")
        self.output_type_var = tk.StringVar(value="Address + Seed + Private")
        
        # Initial options (will be updated by update_output_options)
        options = ["Address + Seed", "Address + Private", "Address + Seed + Private", "Address + Amount"]
        self.output_type_dropdown = ttk.Combobox(self.frame_output_type, values=options, textvariable=self.output_type_var, state="readonly")
        self.output_type_dropdown.pack(fill="x", padx=10, pady=5)
        self.output_type_dropdown.bind("<<ComboboxSelected>>", self.toggle_amount_input)
        
        self.amount_frame = ttk.Frame(parent, style='Main.TFrame')
        self.min_amount_var, self.max_amount_var = tk.StringVar(value="0.001"), tk.StringVar(value="0.05")
        ttk.Label(self.amount_frame, text="Min:").pack(side="left", padx=(10, 5))
        ttk.Entry(self.amount_frame, textvariable=self.min_amount_var, width=8).pack(side="left")
        ttk.Label(self.amount_frame, text="Max:").pack(side="left", padx=(20, 5))
        ttk.Entry(self.amount_frame, textvariable=self.max_amount_var, width=8).pack(side="left")
        
        frame_format = ttk.LabelFrame(parent, text="Output Format")
        frame_format.pack(padx=10, pady=10, fill="x")
        self.format_var = tk.StringVar(value="TXT")
        ttk.Combobox(frame_format, values=["TXT", "CSV", "JSON"], textvariable=self.format_var, state="readonly").pack(fill="x", padx=10, pady=5)
        
        frame_count = ttk.LabelFrame(parent, text="Number of Wallets")
        frame_count.pack(padx=10, pady=10, fill="x")
        self.count_var = tk.IntVar(value=1)
        ttk.Spinbox(frame_count, from_=1, to=10000, textvariable=self.count_var, width=10).pack(padx=10, pady=5)
        
        frame_path = ttk.LabelFrame(parent, text="Output Directory")
        frame_path.pack(padx=10, pady=10, fill="x")
        path_inner_frame = ttk.Frame(frame_path, style='Main.TFrame')
        path_inner_frame.pack(fill='x', padx=10, pady=5)
        self.output_entry = ttk.Entry(path_inner_frame)
        self.output_entry.pack(side="left", fill="x", expand=True, ipady=4)
        ttk.Button(path_inner_frame, text="Browse", command=self.browse, style='TButton').pack(side="left", padx=(10, 0))
        
        ttk.Button(parent, text="Generate Wallets", command=self.generate_wallets).pack(pady=20, ipady=8, fill='x', padx=10)
        
        # Call once at the beginning to set the correct initial state
        self.update_output_options()

    def toggle_amount_input(self, event=None):
        if self.output_type_var.get() == "Address + Amount":
            self.amount_frame.pack(padx=10, pady=5, fill="x", after=self.frame_output_type)
        else:
            self.amount_frame.pack_forget()

    def browse(self):
        path = filedialog.askdirectory()
        if path:
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, path)

    def generate_wallets(self):
        try:
            net = self.network_var.get()
            output_type = self.output_type_var.get()
            count = self.count_var.get()
            out_format = self.format_var.get()
            path = self.output_entry.get()
            if not path or not os.path.isdir(path):
                messagebox.showerror("Error", "A valid output directory must be selected.")
                return
            wallets = []
            if output_type == "Address + Amount":
                min_amount, max_amount = float(self.min_amount_var.get()), float(self.max_amount_var.get())
                if min_amount > max_amount:
                    messagebox.showerror("Error", "Min amount cannot be greater than max amount.")
                    return
                for _ in range(count):
                    wallet = {}
                    if net == "EVM": wallet["address"] = generate_evm_wallet("Address")["address"]
                    elif net == "Solana": wallet["address"] = generate_solana_wallet("Address")["address"]
                    elif net == "Cosmos": wallet["address"] = generate_cosmos_wallet("Address")["address"]
                    wallet["amount"] = f"{random.uniform(min_amount, max_amount):.8f}"
                    wallets.append(wallet)
            else:
                for _ in range(count):
                    if net == "EVM": wallets.append(generate_evm_wallet(output_type))
                    elif net == "Solana": wallets.append(generate_solana_wallet(output_type))
                    elif net == "Cosmos": wallets.append(generate_cosmos_wallet(output_type))
            file_path = save_wallets_to_file(wallets, out_format, path, net, output_type)
            messagebox.showinfo("Success", f"Success!\n{count} wallet(s) saved to:\n{file_path}")
        except ValueError:
            messagebox.showerror("Error", "Invalid input. Please check the amount or number of wallets.")
        except Exception as e:
            error_details = traceback.format_exc()
            messagebox.showerror("An Unexpected Error Occurred", f"Error: {e}\n\nDetails:\n{error_details}")

if __name__ == "__main__":
    root = tk.Tk()
    app = WalletGeneratorApp(root)
    root.mainloop()
