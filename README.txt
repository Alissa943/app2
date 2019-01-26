
The project is an application that provides a list of items and categories as well as provide a user registration and authentication by third party.

# All steps:-

# Install all of follow : 
- Python   2.7.12
- Vagrant v2.2.0  
- VirtualBox v5.1.38 
# Instructions:
1.Create folder that be project folder.
2.Download "Vagrantfile" and place it inside created folder.
3.Run "vagrant up" command inside folder using  git bash and wait till it finish it was take more than 15 min.
4.Run "vagrant ssh" command inside folder using  git bash and wait till it finish it was take more than 5 min.
5.Initialize the database "run" #python database_setup.py
6.Populate the database with catagories "run" python catagories.py.
 the project folder has that files:-
\--- <catalog>
    |   templates
        |   *all .html file 
    |   app.py
    |   catagories.py
    |   client_secrets.json
    |   database_setup.py
    |   static
        |   style.css   
    |   readme
7.Run the Flask web server. In your browser visit http://localhost:8000 to view app.
8. Json endpoints to view any readable data in json format Add **/JSON** to the end of the URL