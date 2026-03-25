import tkinter as tk

root = tk.Tk()                    
root.title("Personal SIEM")       
root.geometry("900x600")         

#left sidebar
sidebar= tk.Frame(root, bg="#0e28ab",width =150)
sidebar.pack(side="left",fill="y")           

#main content area
main_content = tk.Frame(root, bg="#1a1a2e")
main_content.pack(side="right", fill="both", expand=True)

#bottom alert bar
alert=tk.Frame(root, bg="#16213e", height=120)
alert.pack(side="bottom", fill="x")
root.mainloop()                  