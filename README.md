# Item Catalog Projects

> Created By Abdirashiid Jama

## About

This is a website where sport items are listed in a catalog. You can log in with a google acount and add items and edit/delete items that belong to you. 

## To Run

### You will need:
- Python2
- Vagrant
- VirtualBox

### Getting Ready
1. Install Vagrant And VirtualBox
2. Clone this repository
3. Navigate to the Vagrant folder and continue to the catalog folder
4. Start your virtual machine by typing `vagrant up` and then `vagrant ssh` to log in to the machine.



### Running the program

5. type `cd /vagrant` to  navigate to shared folders
6. run the database setup by running the command `python database_setup`
7. then run `injector.py` to populate the database
7. then type `python application.py` to run the application.