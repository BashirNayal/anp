#!/bin/bash
cmake .; make; sudo make install; 
sudo ./bin/sh-hack-anp.sh ./bin/arpdummy
