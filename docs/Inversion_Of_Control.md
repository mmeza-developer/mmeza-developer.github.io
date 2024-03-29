---
title: Inversion Of Control
subtitle: Un pequeño repaso por el concepto de Inversion of Control, junto con la importancia del lenguaje y la historia en desarrollo de software
date: 2024-02-11
tags:
    - Development
---

# Introduccion

Generalmente el concepto de Inversion of Control está relacionado con el patrón Dependecy Injection y Frameworks como Spring. Normalmente los desarrolladores considran ambos conceptos como dos elementso inseparables. Sin embargo, el término IoC es anterior al patrón Dependency Injection .

En esta publicación quisiera mostrar un poco de la historia del término, cual es su real significado y como la historia es también importante en el desarrollo de software.

## ¿Como podriamos definir el término Inversion of Control? 

El siguiente código es un ejemplo práctico en ruby en el que el programa es ejecutado secuencialmente, toma un nombre y una quest y los procesa en el mismo orden con los métodos process_name y process_quest. 

~~~ruby
puts 'What is you name?'
name = gets
process_name(name)
puts 'What is your quest?'
quest= gets
process_quest(quest)
~~~

En el código anterior nos muestra que cada una de las instrucciones dadas por el desarrollador son ejecutadas por programa secuencialmente, sin la necesidad de código de terceros (librerias, Frameworks, etc).


Ahora veamos el siguiente código: 

~~~ruby
require 'tk'
root =TkRoot.new()
name_label =TkLabel.new() {text "What is you name?"} 
name_label.pack
name= TkEntry.new(root).pack
name.bind("FocusOut") {process_name(name)}
quest_label=TkLabel.new() {text "What is your quest?"} 
quest_label.pack
quest= TkEntry.new(root).pack
name.bind("FocusOut") {process_quest(quest)}
Tk.mainloop()
~~~

Lo que hace es:

- Crear un ventana y mostrar el mensaje "What is you name?"
- Recibe el nombre del usuario y lo procesa, pero esta vez en un Closure
- Posteriormente  crea otra venata y muestra el mensaje "What is your quest?"
- Recibe el quest y lo procesa nuevamente en un Closure

Como podemos ver el código de arriba usa una API para crear ventanas o un entorno gráfico en nuestro programa. En este caso, la API toma el control del flujo del software implementado nuestra lógica e incluyendola en la API. Los métodos  `process_name` y `process_quest` son ejecutados por la API a través de un Closure, donde está nuestro código relacionado al negocio

En consecuencia delegamos la ejecución de parte de nuestro código (en este caso parte del negocio de nuestra aplicación) a la API y esto puede entenderse como una inversion del control del flujo del software

Entonces como conclusion, podríamos definir que el concepto de Inversion of Control consiste en que un código de terceros, tales como una librerías, frameworks o APIs toma el control del flujo de ejecución de nuestra aplicación.

## ¿Es correcta la anterior definición? 

Si bien la definción de más arriba es muy ambigua, ya que los lectores mas atentos se habrán dado cuenta que el código secuencial (el primer bloque de código) depende de la API del sistema operativo tanto como el código que utiliza ventanas (segundo bloque de código). La verdad es que por definición estricta del concepto Inversion of Control esta relacionado a los Frameworks. Martin Fowler dice los siguiente:

> When these containers talk about how they are so useful because they implement "Inversion of Control" I end up very puzzled. Inversion of control	is a common characteristic of frameworks, so saying that these lightweight containers are special because they use inversion of control is like saying my car is special because it has wheels.
>
> The question is: "what aspect of control are they inverting?" When I first ran into inversion of control, it was in the main control of a user interface. Early user interfaces were controlled by the application program. You would have a sequence of commands like "Enter name", "enter add Inversion_Of_Controls"; your program would drive the prompts and pick up a response to each one. With graphical (or even screen based) UIs the UI framework would contain this main loop and your program instead provided event handlers for the various fields on the screen. The main control of the program was inverted, moved away from you to the framework.
>
> For this new breed of containers the inversion is about how they lookup a plugin implementation. In my naive example the lister looked up the finder implementation by directly instantiating it. This stops the finder from being a plugin. The approach that these containers use is to ensure that any user of a plugin follows some convention that allows a separate assembler module to inject the implementation into the lister.
>
> As a result I think we need a more specific name for this pattern. Inversion of Control is too generic a term, and thus people find it confusing. As a result with a lot of discussion with various IoC advocates we settled on the name _Dependency Injection_.
>
> I'm going to start by talking about the various forms of dependency injection, but I'll point out now that that's not the only way of removing the dependency from the application class to the plugin implementation. The other pattern you can use to do this is Service Locator, and I'll discuss that after I'm done with explaining Dependency Injection. - Martin Flower

Ademas, Fowler menciona otros autores, que fueron los precursores del término Inversion of Control, estos son Ralph E. Johnson y Brian Foote, ellos escribieron lo siguiente:

> One important characteristic of a framework is that the methods defined by the user to tailor the framework will often be called from within the framework itself, rather than from the user's application code. The framework often plays the role of the main program in coordinating and sequencing application activity. This inversion of control gives frameworks the power to serve as extensible skeletons. The methods supplied by the user tailor the generic algorithms defined in the framework for a particular application. - Designgin Reusable Classes - Ralph E. Johnson & Brian Foote 

# Conclusiones

En base a lo dicho por Matin Fowler, Johnson y Brian Foote, podríamos diferenciar un Framework de una API o librería en que el framework normalmente tiene una estructura definida, permite que el programador cree código bajo ciertas condiciones y limitaciones para posteriormente este código ser ejecutado como parte del framework y no como la aplicación en si misma. En ese sentido un framework cumple la condicion de obtener el control total sobre la ejecución del programa y por consecuencia sobre el código implementado por los desarrolladores.

Por otra parte, el desarrollo de software es una disciplina relativamente reciente, no tiene más de 80 años, además, de ser muy dinámica, en constante evolución y siempre prágmatica. Sin embargo, conocer la historia, no solo de los conceptos sino que tambien de software, librerias, frameworks, etc nos permitirá comprender mejor la tecnología y, por consecuecia, volvernos mejores profesionales.


## Fuentes

[Martin Fowler Inversion of Control](https://www.martinfowler.com/bliki/InversionOfControl.html)

[Designing Reusable Classes](http://www.laputan.org/drc/drc.html)