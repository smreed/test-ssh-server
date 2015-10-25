#!/bin/bash
#sudo docker pull smreed/golang-docker-env
sudo docker run -t -i --rm -p 2222:22 -v $(pwd):/project -v $HOME/.gitconfig:/root/host.gitconfig smreed/golang-docker-env
