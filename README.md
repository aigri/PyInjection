# py-Injection

Voici un script en python qui va se contenter d'injecter du code dans les ELF

## Explication

Celui-ci va chercher si le programme contient deux segments LOAD (qui ont pour flag RWX) pour pouvoir profiter de l'espace disponible entre ceux-ci pour y injecter notre code (qui pourra donc être executé vu le flag 'X' sur les segments). 
Une fois le code injecté il suffit de changer le point d'entrée du programme (qui peut se trouver à l'adresse pointée par le membre e_entry du header ELF32) pour le situer à l'adresse de début de notre code et rajouter une instruction à la fin du code qui va jump sur notre point d'entrée initial

<img src="https://static.packt-cdn.com/products/9781782167105/graphics/7105OS_04_5.jpg">
