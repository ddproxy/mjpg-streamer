export LD_LIBRARY_PATH=.
iso=400
if [ ! -z "$1" ]; then
    iso="$1"
fi

./mjpg_streamer -o "./output_http.so --port 9002 -w ./www" -i "input_raspicam.so -fps 20 -x 800 -y 600 -ISO $iso"
