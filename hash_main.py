from flask import Flask, render_template, request
import hashid
import hashlib
import requests
app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        hash_input = request.form['hash_input']
        hash_types = identify_hash(hash_input)
        if check_hash_pwned(hash_input):
            pawn="This hash has been pwned! It corresponds to a known password."
        else:
            pawn="This hash is not associated with any known password."
        return render_template('hash_index.html', hash_input=hash_input, hash_types=hash_types,pawn=pawn)
    return render_template('hash_index.html')


def identify_hash(hash_value):
    try:
        # Create a hash identifier object
        identifier = hashid.HashID()

        # Identify the hash types
        results = list(identifier.identifyHash(hash_value))
    except Exception as e:
        return None

    # Print the results in a human-readable format
    if results:
        possible_types = []
        for result in results:
            possible_types.append(result.name)
        print(possible_types)
        return possible_types
    else:
        return None


def check_hash_pwned(hash_value):
    # SHA-1 hash value
    sha1_hash = hashlib.sha1(hash_value.encode()).hexdigest().upper()

    # API endpoint for HIBP
    api_url = f'https://api.pwnedpasswords.com/range/{sha1_hash[:5]}'

    # Make the request
    response = requests.get(api_url)

    # Check if the hash appears in the response
    if sha1_hash[5:] in response.text:
        return True
    else:
        return False


if __name__ == '__main__':
    app.run(debug=True)