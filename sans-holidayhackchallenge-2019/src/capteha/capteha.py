#!/usr/bin/python3
# Image Recognition Using Tensorflow Exmaple.
# Code based on example at:
# https://raw.githubusercontent.com/tensorflow/tensorflow/master/tensorflow/examples/label_image/label_image.py
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import tensorflow as tf
tf.logging.set_verbosity(tf.logging.ERROR)
import numpy as np
import threading
import queue
import time
import sys
import re
import base64
import requests

# sudo apt install python3-pip
# sudo python3 -m pip install --upgrade pip
# sudo python3 -m pip install --upgrade setuptools
# sudo python3 -m pip install --upgrade tensorflow==1.15

def load_labels(label_file):
    label = []
    proto_as_ascii_lines = tf.gfile.GFile(label_file).readlines()
    for l in proto_as_ascii_lines:
        label.append(l.rstrip())
    return label

def predict_image(q, sess, graph, image_bytes, img_full_path, labels, input_operation, output_operation):
    image = read_tensor_from_image_bytes(image_bytes)
    results = sess.run(output_operation.outputs[0], {
        input_operation.outputs[0]: image
    })
    results = np.squeeze(results)
    prediction = results.argsort()[-5:][::-1][0]
    q.put( {'img_full_path':img_full_path, 'prediction':labels[prediction].title(), 'percent':results[prediction]} )

def load_graph(model_file):
    graph = tf.Graph()
    graph_def = tf.GraphDef()
    with open(model_file, "rb") as f:
        graph_def.ParseFromString(f.read())
    with graph.as_default():
        tf.import_graph_def(graph_def)
    return graph

def read_tensor_from_image_bytes(imagebytes, input_height=299, input_width=299, input_mean=0, input_std=255):
    image_reader = tf.image.decode_png( imagebytes, channels=3, name="png_reader")
    float_caster = tf.cast(image_reader, tf.float32)
    dims_expander = tf.expand_dims(float_caster, 0)
    resized = tf.image.resize_bilinear(dims_expander, [input_height, input_width])
    normalized = tf.divide(tf.subtract(resized, [input_mean]), [input_std])
    sess = tf.compat.v1.Session()
    result = sess.run(normalized)
    return result

def get_captcha(s):
    r = s.post("https://fridosleigh.com/api/capteha/request")
    assert r.status_code == 200
    labels = r.json()['select_type'].split(',')
    labels = list(map(lambda x: re.sub(r'^ (and )?', '', x), labels))
    label_to_idx = {'Presents': '1',
                    'Candy Canes': '2',
                    'Santa Hats': '3',
                    'Stockings': '4',
                    'Ornaments': '5',
                    'Christmas Trees': '6'}
    indexes = list(map(lambda x: label_to_idx[x], labels))
    return r.json()['images'], labels, indexes

def submit_captcha(s, answer):
    r = s.post("https://fridosleigh.com/api/capteha/submit", data={"answer": ','.join(answer)})
    print(r.content.decode())
    return r.json()['request']

def submit_entry(s):
    r = s.post("https://fridosleigh.com/api/entry", data={"about": "about", "email": "an0n@tuta.io", "age": 180, "name": "nothumanelf", "favorites": "snoweos,cupidcrunch"})
    print(r.content.decode())
    
def main(s):
    # Loading the Trained Machine Learning Model created from running retrain.py on the training_images directory
    graph = load_graph('/tmp/retrain_tmp/output_graph.pb')
    labels = load_labels("/tmp/retrain_tmp/output_labels.txt")

    # Load up our session
    input_operation = graph.get_operation_by_name("import/Placeholder")
    output_operation = graph.get_operation_by_name("import/final_result")
    sess = tf.compat.v1.Session(graph=graph)

    # Can use queues and threading to spead up the processing
    q = queue.Queue()

    # refresh page
    r = s.get("https://fridosleigh.com/")
    assert r.status_code == 200
    print("[+] opened fridosleigh.com")
    
    # get captcha
    images, names, indexes = get_captcha(s)
    print("[+] fetched captcha: {0} images, have to select labels {1}, {2} and {3}".format(len(images), names[0], names[1], names[2]))

    #Going to interate over each of our images.
    print("[*] processing images...")
    for image in images:
        #print('[*] Processing Image with UUID {}'.format(image['uuid']))
        # We don't want to process too many images at once. 10 threads max
        while len(threading.enumerate()) > 500:
            time.sleep(0.0001)

        #predict_image function is expecting png image bytes so we read image as 'rb' to get a bytes object
        image_bytes = base64.b64decode(image['base64'])
        threading.Thread(target=predict_image, args=(q, sess, graph, image_bytes, image['uuid'], labels, input_operation, output_operation)).start()
    
    print('[*] Waiting For Threads to Finish...')
    while q.qsize() < len(images):
        time.sleep(0.001)
    
    #getting a list of all threads returned results
    prediction_results = [q.get() for x in range(q.qsize())]
    
    #do something with our results... Like print them to the screen and select answers
    answer = []
    for prediction in prediction_results:
        if prediction['prediction'] in indexes:
            answer.append(prediction['img_full_path'])
            print('[+] TensorFlow Predicted {img_full_path} is a {prediction} with {percent:.2%} Accuracy'.format(**prediction))

    # submit captcha
    print("[*] submitting answer ({} images selected)".format(len(answer)))
    if submit_captcha(s, answer):
        # submit entry
        while True:
            print("[*] submitting entry")
            submit_entry(s)
    else:
        print("[!] AI error, retrying")

if __name__ == "__main__":
    s = requests.Session()
    while True:
        main(s)
