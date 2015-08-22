export LD_LIBRARY_PATH=.
./mjpg_streamer -o "./output_http.so --port 9002 -w ./www" -i "input_raspicam.so -fps 20 -x 800 -y 600"
