

## My Simple Blog

[How To build it?](https://github.com/gregrickaby/nextjs-github-pages)

I make some change to the Github action config file

I don't know why but, github added a config.next.js file to my project in the docker build instance, so I removed it with following lines:

~~~yml
      - name: Remove next.config.js
        run: rm next.config.js
~~~

