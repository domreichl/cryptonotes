#! python3
# cryptonotes.pyw by Dom Reichl
# simple notepad application with encryption function

import string
from random import shuffle
from tkinter import *
from tkinter import filedialog, messagebox

class Cryptonotes(Frame):
    def __init__(self, master=None, file=None):
        Frame.__init__(self, master)
        self.pack(expand=YES, fill=BOTH)
        self.create_textfield()
        self.create_menubar()
        self.characters = string.ascii_letters + string.digits + '§$&/=?`.°"_,: ;'

    def create_textfield(self):
        scrollbar = Scrollbar(self)
        textarea = Text(self)
        scrollbar.config(command=textarea.yview) # scrollbar interaction
        textarea.config(yscrollcommand=scrollbar.set) # dynamic scrollbar length
        scrollbar.pack(side=RIGHT, fill=Y)
        textarea.pack(side=LEFT, expand=YES, fill=BOTH)
        self.text = textarea
        self.text.focus()

    def create_menubar(self):
        menubar = Menu(self)
        self.master.config(menu=menubar)
        
        file = Menu(menubar, tearoff=False)
        menubar.add_cascade(label="File", menu=file)
        file.add_command(label='New', command=self.new)

        openfile = Menu(file, tearoff=False)
        file.add_cascade(label='Open   ', menu=openfile)
        openfile.add_command(label='Normal', command=self.normal_open)
        openfile.add_command(label='Decrypt', command=self.decrypt_open)

        savefile = Menu(file, tearoff=False)
        file.add_cascade(label='Save   ', menu=savefile)
        savefile.add_command(label='Normal', command=self.normal_save)
        savefile.add_command(label='Encrypt', command=self.encrypt_save)

        file.add_command(label='Close', command=root.destroy)

        edit = Menu(menubar, tearoff=False)
        menubar.add_cascade(label='Edit', menu=edit)
        edit.add_command(label='Cut', command=self.cut)
        edit.add_command(label='Copy', command=self.copy)
        edit.add_command(label='Paste', command=self.paste)

    def new(self):
        self.text.delete('1.0', END)

    def normal_open(self):
        loadedfile = filedialog.askopenfile(filetypes=[('Text File', '.txt')])
        if loadedfile == None:
            return
        else:
            normal_text = loadedfile.read()
        if normal_text.startswith("***encrypted file***"):
            normal_text = normal_text.strip("***encrypted file***")
            messagebox.showwarning("Dom's Cryptonotes", "This file is encrypted.")
        self.text.delete('1.0', END)
        self.text.insert('1.0', normal_text)

    def normal_save(self):
        filename = filedialog.asksaveasfilename(filetypes=[('Text File', '.txt')])
        if filename == "":
            return
        else:
            with open(filename + '.txt', 'w') as fn:
                fn.write(self.text.get('1.0', END+'-1c'))
                messagebox.showinfo("Dom's Cryptonotes", "File saved.")

    def decrypt_open(self):
        loadedfile = filedialog.askopenfile(filetypes=[('Text File', '.txt')])
        if loadedfile == None:
            return
        else:
            encrypted_text = loadedfile.read()
        normal_text = self.decrypt(encrypted_text)
        self.text.delete('1.0', END)
        self.text.insert('1.0', normal_text)

    def decrypt(self, encrypted_text):
        if encrypted_text.startswith("***encrypted file***"):
            encrypted_text = encrypted_text.strip("***encrypted file***")
        else:
            messagebox.showwarning("Dom's Cryptonotes", "This file is not encrypted.")
            return encrypted_text
        key_length = len(self.characters)
        key = encrypted_text[:5] + encrypted_text[-key_length+5:]
        ciphertext = encrypted_text[5:-key_length+5]
        decrypted_text = ""
        for i in range(len(ciphertext)):
            if ciphertext[i] in self.characters:
                for j in range(key_length):
                    if ciphertext[i] == key[j]:
                        decrypted_text = decrypted_text + self.characters[j]
            else:
                decrypted_text = decrypted_text + ciphertext[i]
        return decrypted_text

    def encrypt_save(self):
        filename = filedialog.asksaveasfilename(filetypes=[('Text File', '.txt')])
        if filename == "":
            return
        else:
            with open(filename + '.txt', 'w') as fn:
                fn.write(self.encrypt(self.text.get('1.0', END+'-1c')))
                messagebox.showinfo("Dom's Cryptonotes", "File encrypted and saved.")

    def encrypt(self, normal_text):
        charlist = [i for i in self.characters]
        shuffle(charlist)
        ciphertext = ""
        for i in normal_text:
            if i in self.characters:
                ciphertext = ciphertext + charlist[self.characters.index(i)]
            else:
                ciphertext = ciphertext + i
        key = ''.join(charlist)
        encrypted_text = "***encrypted file***" + key[:5] + ciphertext + key[5:]
        return encrypted_text

    def cut(self):
        if not self.text.tag_ranges(SEL):
            messagebox.showerror("Dom's Cryptonotes", "No text selected.")
        else:
            self.copy()
            self.text.delete(SEL_FIRST, SEL_LAST)

    def copy(self):
        if not self.text.tag_ranges(SEL):
            messagebox.showerror("Dom's Cryptonotes", "No text selected.")
        else:
            selected_text = self.text.get(SEL_FIRST, SEL_LAST)
            self.clipboard_clear()
            self.clipboard_append(selected_text)

    def paste(self):
        try:
            pastetext = self.clipboard_get()
        except TclError:
            showerror("Dom's Cryptonotes", "Nothing to paste")
            return
        if self.text.tag_ranges(SEL):
            self.text.delete(SEL_FIRST, SEL_LAST) # delete selected text
        self.text.insert(INSERT, pastetext) # insert text
        # select pasted text
        self.text.tag_remove(SEL, '1.0', END)
        self.text.tag_add(SEL, INSERT+'-%dc' % len(pastetext), INSERT)
        self.text.see(INSERT)

root = Tk()
app = Cryptonotes(master=root)
app.master.title("Dom's Cryptonotes")
app.mainloop()
