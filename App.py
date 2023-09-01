import os
import sys
import customtkinter
import json
import unidecode
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from random import randrange
from tkinter import messagebox
passw = ""
file_dir = ""
app_folder = "\Enc_App"
control = 0

turkish_to_english = {
    'ğ': 'g', 'ı': 'i', 'ş': 's', 'ç': 'c', 'ü': 'u', 'ö': 'o',
    'Ğ': 'G', 'İ': 'I', 'Ş': 'S', 'Ç': 'C', 'Ü': 'U', 'Ö': 'O'
}

class Scrollable_Folder_Menu(customtkinter.CTkScrollableFrame):
    def __init__(self, master, command=None, **kwargs):
        super().__init__(master, **kwargs)
        self.grid_columnconfigure(0, weight=1)

        self.command = command
        self.radiobutton_variable = customtkinter.StringVar()
        self.label_list = []
        self.button_list = []

    def add_item(self, item, image=None):
        label = customtkinter.CTkLabel(self, text=item, image=image, compound="left", padx=5, anchor="w")
        button = customtkinter.CTkButton(self, text="Select", width=100, height=24)
        if self.command is not None:
            button.configure(command=lambda: self.command(item))
        label.grid(row=len(self.label_list), column=0, pady=(0, 10), sticky="w")
        button.grid(row=len(self.button_list), column=1, pady=(0, 10), padx=5)
        self.label_list.append(label)
        self.button_list.append(button)

    def remove_item(self, item):
        for label, button in zip(self.label_list, self.button_list):
            if item == label.cget("text"):
                label.destroy()
                button.destroy()
                self.label_list.remove(label)
                self.button_list.remove(button)
                return

class ScrollableLabelButtonFrame(customtkinter.CTkScrollableFrame):


    def __init__(self, master, command=None, command2=None,label=None, **kwargs):
        super().__init__(master, **kwargs)
        self.grid_columnconfigure(0, weight=1)
        self.command = command
        self.command2 = command2
        self.label = label
        self.radiobutton_variable = customtkinter.StringVar()
        self.label_list = []
        self.button_list = []
        self.button_list2 = []
    def add_item(self, item, image=None):
        label = customtkinter.CTkLabel(self, text=item, image=image, compound="left", padx=5, anchor="w")
        button = customtkinter.CTkButton(self, text="Destroy", width=60, height=24)
        button2 = customtkinter.CTkButton(self, text=self.label, width=60, height=24)
        if self.command is not None:
            button.configure(command=lambda: self.command(item))
        if self.command2 is not None:
            button2.configure(command=lambda: self.command2(item))
        label.grid(row=len(self.label_list), column=0, pady=(0, 10), sticky="w")
        button.grid(row=len(self.button_list), column=1, pady=(0, 10), padx=5)
        button2.grid(row=len(self.button_list), column=2, pady=(0, 10), padx=5)
        self.label_list.append(label)
        self.button_list.append(button)
        self.button_list2.append(button2)

    def remove_item(self, item):
        for label, button, button2 in zip(self.label_list, self.button_list,self.button_list2):
            if item == label.cget("text"):
                label.destroy()
                button.destroy()
                button2.destroy()
                self.label_list.remove(label)
                self.button_list.remove(button)
                self.button_list2.remove(button2)
                return

    def get_checked_items(self):
        return [checkbox.cget("text") for checkbox in self.checkbox_list if checkbox.get() == 1]

class folder_file_name:
    def __init__(self):

        self.script_path = sys.argv[0]
        self.script_name = os.path.basename(self.script_path)

        index = self.script_path.rfind("\\")
        self.current_dir = self.script_path[:index]

    def get_subfolder_paths(self):
        subfolder_paths = []
        subfolder_clear_paths = []


        for root, dirs, files in os.walk(self.current_dir):
            for dir_name in dirs:
                subfolder_paths.append(os.path.join(root, dir_name))


        for path in subfolder_paths:
            subfolder_clear_paths.append(path.replace(self.current_dir, ""))


        subfolder_clear_paths.remove(app_folder)

        return subfolder_clear_paths

    def get_files_in_folder(self, path, action=None):

        folder_path = self.current_dir + path

        print(folder_path)

        file_list = []

        for folder_path, subfolders, file_names in os.walk(folder_path):
            for file in file_names:
                if action == "Encrypt":
                    if file.endswith(".aes") == False:
                        file_list.append(file)

                elif action == "Decrypt":
                    if file.endswith(".aes") == True:
                        file_list.append(file)

        return file_list

    def find_file(self,filename, current_path=None):


        if current_path.find(self.current_dir) < 0:
            current_path = self.current_dir + current_path
        for root, dirs, files in os.walk(current_path):

            if filename in files:

                return os.path.join(root, filename), current_path
        return None

class App:
    global encryption_obj
    global decryption_obj
    global folder_file_name_obj
    def __init__(self):
        global password_entry

        self.script_path = sys.argv[0]
        self.script_name = os.path.basename(self.script_path)

        index = self.script_path.rfind("\\")
        self.current_dir = self.script_path[:index]

        self.main_window = customtkinter.CTk()
        self.main_window.geometry('350x150')
        if os.path.exists(self.current_dir + app_folder + '\icon.ico'):
            self.main_window.iconbitmap(self.current_dir + app_folder + '\icon.ico')
        self.main_window.title("Encryption")
        self.main_window.resizable(False, False)
        self.encrypt_win_button = customtkinter.CTkButton(master=self.main_window, text="Encrypt",
                                                          command=self.folder_menu_open_enc)
        self.encrypt_win_button.pack(side="left")

        self.decrypt_win_button = customtkinter.CTkButton(master=self.main_window, text="Decrypt",
                                                          command=self.folder_menu_open_dec)
        self.decrypt_win_button.pack(side="right")

        # Create labels and entry fields
        self.password_label = customtkinter.CTkLabel(master=self.main_window, text="Password:")
        self.password_label.pack()

        self.password_entry = customtkinter.CTkEntry(self.main_window, textvariable=None, height=22, width=200,
                                                     show="*")  # Use 'show' to hide the entered characters
        self.password_entry.place(relx=0.2, rely=0.2)

        self.main_window.protocol("WM_DELETE_WINDOW", self.on_closing)


    def on_closing(self):

        try:
            self.folder_menu.destroy()
        except:
            pass
        try:
            self.encryption_menu.destroy()

        except:
            pass
        try:
            self.folder_menu.destroy()
        except:
            pass
        try:
            self.main_window.destroy()
        except:
            pass
        os._exit(0)

    def dark_error(self, message):
        error_dialog = customtkinter.CTkToplevel(self.main_window)
        error_dialog.title("Dark Mode Error")
        error_dialog.configure(bg="black")  # Set background color to black or any dark color

        error_label = customtkinter.CTkLabel(error_dialog, text=message)
        error_label.pack(padx=20, pady=20)

    def folder_menu_open_enc(self):
        global control
        global passw
        passw = self.password_entry.get()
        pass_check()
        if not control == 1:
            return

        self.main_window.withdraw()
        self.folder_menu = customtkinter.CTkToplevel(self.main_window)
        self.folder_menu.title("Select_Folder")
        self.folder_menu.geometry('440x500')
        self.folder_menu.resizable(False, False)
        self.folder_menu.protocol("WM_DELETE_WINDOW", self.folder_menu_close)

        scrollable_folder_menu = Scrollable_Folder_Menu(master=self.folder_menu, width=420, height=500,
                                                            corner_radius=0,
                                                            command=self.encryption_menu_open)
        scrollable_folder_menu.place(relx=0, rely=0.01)

        for subfolder in folder_file_name_obj.get_subfolder_paths():
            scrollable_folder_menu.add_item(subfolder)

    def folder_menu_open_dec(self):
        global control
        global passw
        passw = self.password_entry.get()
        pass_check()
        if not control == 1:
            return

        self.main_window.withdraw()
        self.folder_menu = customtkinter.CTkToplevel(self.main_window)
        self.folder_menu.title("Select_Folder")
        self.folder_menu.geometry('440x500')
        self.folder_menu.resizable(False, False)
        self.folder_menu.protocol("WM_DELETE_WINDOW", self.folder_menu_close)

        scrollable_folder_menu = Scrollable_Folder_Menu(master=self.folder_menu, width=420, height=500,
                                                            corner_radius=0,
                                                            command=self.decryption_menu_open)
        scrollable_folder_menu.place(relx=0, rely=0.01)

        for subfolder in folder_file_name_obj.get_subfolder_paths():
            scrollable_folder_menu.add_item(subfolder)
    def folder_menu_close(self):
        self.folder_menu.destroy()
        self.main_window.deiconify()

    def encryption_menu_open(self, current_folder_path):
        global passw
        global file_dir
        global scrollable_encryption_menu
        file_dir = current_folder_path
        passw = self.password_entry.get()
        self.folder_menu.destroy()
        self.encryption_menu = customtkinter.CTkToplevel(self.main_window)
        self.encryption_menu.title("Encrypt")
        self.encryption_menu.geometry('350x500')
        self.encryption_menu.resizable(False, False)
        self.encryption_menu.protocol("WM_DELETE_WINDOW", self.encryption_menu_close)
        scrollable_encryption_menu = ScrollableLabelButtonFrame(master=self.encryption_menu, width=340, height=500,
                                                                corner_radius=0,
                                                                command=encryption_obj.remove_fonction, command2=encryption_obj.encrypt_it, label="Encrypt")
        scrollable_encryption_menu.place(relx=0, rely=0.01)


        for file in folder_file_name_obj.get_files_in_folder(current_folder_path, action="Encrypt"):
            scrollable_encryption_menu.add_item(file)

    def encryption_menu_close(self):
        self.encryption_menu.destroy()
        self.folder_menu_open_enc()

    def decryption_menu_open(self, current_folder_path):
        global passw
        global file_dir
        global scrollable_decryption_menu

        file_dir = current_folder_path
        passw = self.password_entry.get()

        self.folder_menu.destroy()
        self.decryption_menu = customtkinter.CTkToplevel(self.main_window)
        self.decryption_menu.title("Decrypt")
        self.decryption_menu.geometry('350x500')
        self.decryption_menu.resizable(False, False)
        self.decryption_menu.protocol("WM_DELETE_WINDOW", self.decryption_menu_close)

        scrollable_decryption_menu = ScrollableLabelButtonFrame(master=self.decryption_menu, width=340, height=500,
                                                                corner_radius=0,
                                                                command=decryption_obj.remove_fonction,
                                                                command2=decryption_obj.decrypt_it, label="Decrypt")
        scrollable_decryption_menu.place(relx=0, rely=0.01)

        for file in manage_file_names_obj.decrypt_name_list(folder_file_name_obj.get_files_in_folder(file_dir,action="Decrypt"), file_dir):
            scrollable_decryption_menu.add_item(file)

    def decryption_menu_close(self):
        self.decryption_menu.destroy()
        self.folder_menu_open_dec()
class pass_check:
    def __init__(self):
        self.script_path = sys.argv[0]
        index = self.script_path.rfind("\\")
        self.current_dir = self.script_path[:index]
        self.folder = self.current_dir + app_folder

        if not os.path.exists(self.folder):
            os.makedirs(self.folder)

        if not os.path.exists(self.folder+"\\00000000.aes"):
            self.create_pass_file()
        elif os.path.exists(self.folder+"\\00000000.aes"):
            self.pass_check()

    def create_pass_file(self):
        global passw
        global control

        try:
            salt = get_random_bytes(32)
            key = PBKDF2(passw, salt, dkLen=32)
            cipher = AES.new(key, AES.MODE_CBC)
            data = get_random_bytes(128)
            ciphered_data = cipher.encrypt(pad(data, AES.block_size))

            with open(self.folder+"\\00000000.aes", "wb") as fOut:
                fOut.write(salt)
                fOut.write(cipher.iv)
                fOut.write(ciphered_data)

            print("File Created")
            control = 1
        except Exception as e:
            app_obj.dark_error(e)
            print("Error Create_Pass_File")
            control = 0

    def pass_check(self):
        global control
        global passw

        try:
            with open(self.folder+"\\00000000.aes", "rb") as fIn:
                salt = fIn.read(32)
                iv = fIn.read(16)
                data = fIn.read()

            key = PBKDF2(passw, salt, dkLen=32)
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            decrypted_data = unpad(cipher.decrypt(data), AES.block_size)
            control = 1
            print("Pass Verified")
        except ValueError:
            control = 0
            app_obj.dark_error("Wrong Password!!!")
            print("Wrong password")
        except:
            print("Error")


class manage_file_names:
    global app_obj
    global passw
    def __init__(self, name=None, encrypted_name=None, action=None):
        self.name = name
        self.encrypted_name = encrypted_name
        self.script_path = sys.argv[0]
        index = self.script_path.rfind("\\")
        self.current_dir = self.script_path[:index]
        self.folder = self.current_dir + app_folder
        self.file_path = self.current_dir + app_folder + "\File_Names.txt"




    def initialize_mappings_file(self):

        if not os.path.exists(self.folder):
            os.makedirs(self.folder)

        if not os.path.exists(self.file_path):
            initial_data = {"file_mappings": {}}
            with open(self.file_path, 'w') as file:
                json.dump(initial_data, file, indent=4)

    def load_mappings(self):
        try:
            with open(self.file_path, 'r') as file:
                data = json.load(file)
                return data.get("file_mappings", {})
        except FileNotFoundError:
            return {}

    def add_mapping(self):
        self.initialize_mappings_file()
        data = self.load_mappings()
        data[self.name] = self.encrypted_name
        with open(self.file_path, 'w') as file:
            json.dump({"file_mappings": data}, file, indent=4)

    def remove_mapping(self, file_name):
        data = self.load_mappings()
        if file_name in data:
            del data[file_name]
            with open(self.file_path, 'w') as file:
                json.dump({"file_mappings": data}, file, indent=4)
            print(f"Mapping for '{file_name}' removed.")
        else:
            print(f"No mapping found for '{file_name}'.")
    def encrypt_name(self,file_path, current_dir, original_name):
        global turkish_to_english

        try:
            name = str(randrange(10000000,99999999))
            self.name = name
            passw = app.password_entry.get()
            with open(file_path + ".aes", "rb") as f:
                salt = f.read(32)
                iv = f.read(16)
            key = PBKDF2(passw, salt, dkLen=32)
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)

            original_name = original_name.encode('ascii')
            ciphered_data = cipher.encrypt(pad(original_name, AES.block_size))
            self.encrypted_name = ciphered_data.hex()
            self.add_mapping()
            current_dir = file_path.replace(str(original_name)[2:-1],"")
            os.rename(file_path+".aes", current_dir + "\\" + name +".aes")
            print("File Rename Done")
            return True
        except:
            print("hata")
            return False

    def decrypt_name_list(self, file_names, current_file_dir):
        global original_names_assigned
        original_names = []
        original_names_assigned = {}
        for file in file_names:


            file_path, current_file_dir = folder_file_name_obj.find_file(file, current_path=current_file_dir)
            name = file.replace(".aes","")
            self.name = name
            data = self.load_mappings()
            message = bytes.fromhex(data[name])

            with open(file_path, "rb") as f:
                salt = f.read(32)
                iv = f.read(16)
            key = PBKDF2(passw, salt, dkLen=32)
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            original_name = unpad(cipher.decrypt(message), AES.block_size)
            original_names_assigned[name] = original_name
            original_names.append(original_name)
        return original_names

class encryption:
    global folder_file_name_obj
    global manage_file_names_obj
    def __init__(self):

        pass


    def encrypt_it(self,file_name):
        global passw
        global file_dir
        global scrollable_encryption_menu
        try:
            file_path, current_dir = folder_file_name_obj.find_file(file_name, file_dir)
            salt = get_random_bytes(32)
            key = PBKDF2(passw, salt, dkLen=32)
            cipher = AES.new(key, AES.MODE_CBC)

            #read the file
            with open(file_path, "rb") as fIn:
                data = fIn.read()
            ciphered_data = cipher.encrypt(pad(data, AES.block_size))
            #create the file

            translation_table = str.maketrans(turkish_to_english)
            original_name_non = file_name.translate(translation_table)

            file_path_to_write = file_path.replace(file_name, original_name_non)
            print(file_path)
            with open(file_path_to_write+".aes", "wb") as fOut:
                fOut.write(salt)
                fOut.write(cipher.iv)
                fOut.write(ciphered_data)
            print("successfully encrypted")
            if manage_file_names_obj.encrypt_name(file_path_to_write, current_dir, original_name_non) == True:
                self.remove(file_path)
            print("Done")
            scrollable_encryption_menu.remove_item(file_name)

        except Exception as e:
            app_obj.dark_error(e)

            return False


    def remove_fonction(self,file_name):
        global passw
        global file_dir
        global scrollable_encryption_menu

        scrollable_encryption_menu.remove_item(file_name)
        try:
            file_path, current_dir = folder_file_name_obj.find_file(file_name, file_dir)
            self.remove(file_path)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")


    def remove(self, path):
        passes = 1
        for data in range(0, 10):
            with open(path, "ba+") as delfile:
                length = delfile.tell()
            with open(path, "br+") as delfile:
                for i in range(passes):
                    delfile.seek(0)
                    delfile.write(os.urandom(length))
        os.remove(path)

class decryption:

    def decrypt_it(self, file_name):
        global passw
        global file_dir
        global original_names_assigned
        global scrollable_decryption_menu
        original_names_assigned_inv =  {v: k for k, v in original_names_assigned.items()}


        try:
            file_path_encrypted_name, current_dir = folder_file_name_obj.find_file(original_names_assigned_inv[file_name]+".aes", file_dir)
            current_dir = file_path_encrypted_name.replace(original_names_assigned_inv[file_name]+".aes", "")
            file_path_decrypted_name = current_dir + "\\" + str(file_name)[2:-1]
            print(current_dir)
            with open(file_path_encrypted_name, "rb") as fIn:
                salt = fIn.read(32)
                iv = fIn.read(16)
                data = fIn.read()
            print("read")
            key = PBKDF2(passw, salt, dkLen=32)
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            decrypted_data = unpad(cipher.decrypt(data), AES.block_size)
            with open(file_path_decrypted_name, "wb") as fOut:
                fOut.write(decrypted_data)
            print("successfully decrypted")
            self.remove(file_path_encrypted_name)
            print(original_names_assigned_inv[file_name])
            manage_file_names_obj.remove_mapping(original_names_assigned_inv[file_name])
            print("sucesfully removed file")
            scrollable_decryption_menu.remove_item(file_name)
            return True
        except Exception as e:
            app_obj.dark_error(e)

            return False

    def remove_fonction(self,file_name):
        global file_dir
        global original_names_assigned
        global scrollable_decryption_menu
        original_names_assigned_inv = {v: k for k, v in original_names_assigned.items()}

        scrollable_decryption_menu.remove_item(file_name)
        try:
            file_path_encrypted_name, current_dir = folder_file_name_obj.find_file(original_names_assigned_inv[file_name] + ".aes", file_dir)
            self.remove(file_path_encrypted_name)
        except:
            print("error Remove_Fonction_Decrypt")

    def remove(self, path):
        passes = 1
        for data in range(0, 10):
            with open(path, "ba+") as delfile:
                length = delfile.tell()
            with open(path, "br+") as delfile:
                for i in range(passes):
                    delfile.seek(0)
                    delfile.write(os.urandom(length))
        os.remove(path)

encryption_obj = encryption()
decryption_obj = decryption()
app_obj = App()
folder_file_name_obj = folder_file_name()
manage_file_names_obj = manage_file_names()
if __name__ == '__main__':
    app = App()

    app.main_window.mainloop()
