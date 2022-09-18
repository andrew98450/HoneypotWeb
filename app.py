import os
import numpy
import configparser
import matplotlib.pyplot as plt
import tflite_runtime.interpreter as tflite
from flask import *
from telegram import *
from telegram.ext import *

config = configparser.ConfigParser()
config.read("./config.conf")
api_token = str(config.get('env', 'api_token'))
bot = Bot(api_token)
dispatcher = Dispatcher(bot, None)
app = Flask(__name__)

def start(update : Update, context : CallbackContext):
    help_str = """
    /start -> Output Help Menu.\n/generate <n> -> Generate N * N random MNIST image.
    """
    update.message.reply_text(help_str)

def generate_image(update : Update, context : CallbackContext):
    if len(context.args) == 0:
        update.message.reply_text("Please Input N.")
        return
    n = int(context.args[0])

    model = tflite.Interpreter("./mnist_random_model.tflite")
    model.allocate_tensors()

    input_details = model.get_input_details()[0]
    output_details = model.get_output_details()[0]
    sample = n ** 2
    z_inputs = numpy.random.normal(size=(sample, 128))

    plt.figure()
    for i in range(sample):
         
        inputs = numpy.array(numpy.expand_dims(z_inputs[i], 0), dtype=numpy.float32)   
        model.set_tensor(input_details['index'], inputs)

        model.invoke()

        outputs = model.get_tensor(output_details['index'])
        outputs = 0.5 * outputs + 0.5
        outputs *= 255.0
        img = outputs.squeeze()

        plt.subplot(n, n, i + 1)
        plt.axis('off')
        plt.imshow(img, cmap="gray")
      
    plt.tight_layout()
    plt.savefig("temp.jpg")
    update.message.reply_photo(open("temp.jpg", "rb"))
    update.message.reply_text("ok")
    
dispatcher.add_handler(CommandHandler("start", start))
dispatcher.add_handler(CommandHandler("generate", generate_image))

@app.route("/webhook", methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        update = Update.de_json(request.get_json(force=True), bot)
        dispatcher.process_update(update)
        return "Success."
    return "ok"

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(os.environ.get('PORT', 8080)), debug=True)
    
