#! python3
# cryptonotes.pyw by Dom Reichl

import string
from random import shuffle
from tkinter import *
from tkinter import filedialog, messagebox

class Cryptonotes(Frame):
    ''' A simple notepad application with encryption function '''
    
    def __init__(self, master=None, file=None):
        '''
        Initializes master frame with pack geometry.
        Creates a field for entering text and a menu bar for file and edit functions.
        Assigns character pool for encryption as string to variable 'self.characters'.
        '''
        
        Frame.__init__(self, master)
        self.pack(expand=YES, fill=BOTH)
        self.create_textfield()
        self.create_menubar()
        self.characters = string.ascii_letters + string.digits + '§$&/=?`.°"_,: ;'

    def create_textfield(self):
        ''' Creates text entry widget with dynamic scrollbar. '''
        
        scrollbar = Scrollbar(self)
        textarea = Text(self)
        scrollbar.config(command=textarea.yview) # scrollbar interaction
        textarea.config(yscrollcommand=scrollbar.set) # dynamic scrollbar length
        scrollbar.pack(side=RIGHT, fill=Y)
        textarea.pack(side=LEFT, expand=YES, fill=BOTH)
        self.text = textarea
        self.text.focus() # saves user one click

    def create_menubar(self):
        ''' Creates menu widget for file and edit functions. '''
        
        # create menu widget
        menubar = Menu(self)
        self.master.config(menu=menubar)
        
        # create cascade for file functions
        file = Menu(menubar, tearoff=False)
        menubar.add_cascade(label="File", menu=file)
        file.add_command(label='New', command=self.new)
        
        # create subcascade for opening files
        openfile = Menu(file, tearoff=False)
        file.add_cascade(label='Open   ', menu=openfile)
        openfile.add_command(label='Normal', command=self.normal_open)
        openfile.add_command(label='Decrypt', command=self.decrypt_open)

        # create subcascade for saving files
        savefile = Menu(file, tearoff=False)
        file.add_cascade(label='Save   ', menu=savefile)
        savefile.add_command(label='Normal', command=self.normal_save)
        savefile.add_command(label='Encrypt', command=self.encrypt_save)

        file.add_command(label='Close', command=root.destroy)

        # create cascade for edit functions
        edit = Menu(menubar, tearoff=False)
        menubar.add_cascade(label='Edit', menu=edit)
        edit.add_command(label='Cut', command=self.cut)
        edit.add_command(label='Copy', command=self.copy)
        edit.add_command(label='Paste', command=self.paste)

    def new(self):
        ''' Empties text area. '''
        
        self.text.delete('1.0', END)

    def normal_open(self):
        ''' Opens text file in normal mode. '''
        
        loadedfile = filedialog.askopenfile(filetypes=[('Text File', '.txt')]) # dialog box for selecting file
        if loadedfile == None: # make sure user has not canceled file selection
            return
        else:
            normal_text = loadedfile.read()
        if normal_text.startswith("***encrypted file***"): # check whether file is normal or encrypted
            normal_text = normal_text.strip("***encrypted file***")
            messagebox.showwarning("Dom's Cryptonotes", "This file is encrypted.")
        self.new() # empty text area
        self.text.insert('1.0', normal_text)

    def normal_save(self):
        ''' Saves text as file in normal mode. '''
        
        filename = filedialog.asksaveasfilename(filetypes=[('Text File', '.txt')])
        if filename == "": # make sure user has not canceled the dialog box
            return
        else:
            with open(filename + '.txt', 'w') as fn:
                fn.write(self.text.get('1.0', END+'-1c'))
                messagebox.showinfo("Dom's Cryptonotes", "File saved.")

    def decrypt_open(self):
        ''' Opens text file in decryption mode. '''
        
        loadedfile = filedialog.askopenfile(filetypes=[('Text File', '.txt')])
        if loadedfile == None: # make sure user has not canceled file selection
            return
        else:
            encrypted_text = loadedfile.read()
        normal_text = self.decrypt(encrypted_text)
        self.new() # empty text area
        self.text.insert('1.0', normal_text)

    def decrypt(self, encrypted_text):
        ''' Decrypts text. '''
        
        if encrypted_text.startswith("***encrypted file***"): # check whether file is actually encrypted
            encrypted_text = encrypted_text.strip("***encrypted file***") # remove encryption tag
        else:
            messagebox.showwarning("Dom's Cryptonotes", "This file is not encrypted.")
            return encrypted_text # returns text to insert into text widget without further processing
        key_length = len(self.characters) # get length of encryption key
        key = encrypted_text[:5] + encrypted_text[-key_length+5:] # extract key from text
        ciphertext = encrypted_text[5:-key_length+5] # extract actual text
        decrypted_text = ""
        for i in range(len(ciphertext)): # iterate through every character in the text
            if ciphertext[i] in self.characters: 
                for j in range(key_length): # iterate through every character in the key
                    if ciphertext[i] == key[j]:
                        decrypted_text = decrypted_text + self.characters[j] # resubstitute character
            else: # some special characters don't need decryption
                decrypted_text = decrypted_text + ciphertext[i]
        return decrypted_text

    def encrypt_save(self):
        ''' Saves text as file in encryption mode. '''
        
        filename = filedialog.asksaveasfilename(filetypes=[('Text File', '.txt')])
        if filename == "": # make sure user has not canceled the dialog box
            return
        else:
            with open(filename + '.txt', 'w') as fn:
                fn.write(self.encrypt(self.text.get('1.0', END+'-1c'))) # get text, encrypt it, and write it into file
                messagebox.showinfo("Dom's Cryptonotes", "File encrypted and saved.")

    def encrypt(self, normal_text):
        ''' Encrypts text. '''
        
        charlist = [i for i in self.characters] # turns string into list
        shuffle(charlist) # randomizes characters in list
        ciphertext = ""
        for i in normal_text:
            if i in self.characters:
                ciphertext = ciphertext + charlist[self.characters.index(i)] # substitute character
            else: # some special characters aren't substituted
                ciphertext = ciphertext + i
        key = ''.join(charlist) # turn shuffled character list into string
        encrypted_text = "***encrypted file***" + key[:5] + ciphertext + key[5:] # add encryption tag and enclose text within two parts of the key string
        return encrypted_text

    def cut(self):
        ''' Allows user to cut selected text. '''
        
        self.copy() # calls function to store text in clipboard
        self.text.delete(SEL_FIRST, SEL_LAST)

    def copy(self):
        ''' Allows user to copy selected text to clipboard. '''
        
        if not self.text.tag_ranges(SEL):
            messagebox.showerror("Dom's Cryptonotes", "No text selected.")
        else:
            selected_text = self.text.get(SEL_FIRST, SEL_LAST)
            self.clipboard_clear()
            self.clipboard_append(selected_text)

    def paste(self):
        ''' Allows user to paste text from clipboard. '''
        
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
