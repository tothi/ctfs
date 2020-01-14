#!/bin/bash
#
# manually classify images

TRAINDATA="./traindata"
IMGROOT="./training_images"
ACTION1=${IMGROOT}/1
ACTION2=${IMGROOT}/2
ACTION3=${IMGROOT}/3
ACTION4=${IMGROOT}/4
ACTION5=${IMGROOT}/5
ACTION6=${IMGROOT}/6

cat <<EOF
1: Presents
2: Candy Canes
3: Santa Hats
4: Stockings
5: Ornaments
6: Christmas Trees
EOF

find $TRAINDATA -type f -name "*.png" | \
    feh --action1 "mv %F ${ACTION1}/%N" \
	--action2 "mv %F ${ACTION2}/%N" \
	--action3 "mv %F ${ACTION3}/%N" \
	--action4 "mv %F ${ACTION4}/%N" \
	--action5 "mv %F ${ACTION5}/%N" \
	--action6 "mv %F ${ACTION6}/%N" -f -
