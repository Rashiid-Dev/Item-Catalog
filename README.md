# Item Catalog Project

> Created By Abdirashiid Jama

## About

This is a website where sport items are listed in a catalog. You can log in with a google acount and add items and edit/delete items that belong to you. 

## To Run

### You will need:
- [Python2](https://www.python.org/)
- [Vagrant](https://www.vagrantup.com/)
- [VirtualBox](https://www.virtualbox.org/) or a Linux-based virtual machine
- [Flask](http://flask.pocoo.org/)

#### and dependencies:

- oauth2client
- SQLAlchemy
- PostgreSQL
- httlib2

### Getting Ready
1. Install Vagrant And VirtualBox
2. Clone this repository
3. Navigate to the Vagrant folder and continue to the catalog folder
4. Start your virtual machine by typing `vagrant up` and then `vagrant ssh` to log in to the machine.



### Running the program

5. type `cd /vagrant` to  navigate to shared folders
6. to get all the dependencies run `pip install -r requirements.txt` 
(if you get a `ERROR: Could not install packages` error, use the sudo command like this `sudo pip install -r requirements.txt`)
7. then navigate to catalog project by typing `cd catalog`
8. run the database setup by running the command `python database_setup`
9. then run `python injector.py` to populate the database
10. then type `python application.py` to run the application.
