#!/usr/bin/env bash

echo make sure you have postgres etc running locally still
docker build -t osiraa-dev -f Dockerfile-dev . 
docker run -it --net=host -v $PWD/drp_aa_mvp:/code osiraa-dev 
