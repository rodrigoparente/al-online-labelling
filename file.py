# python imports
import os
import json
import pickle


# check and create folder it doesn't exists
def create_if_dont_exists(path):
    dirs = os.path.split(path)[0]
    if not os.path.exists(dirs):
        os.makedirs(dirs)


def save_df(path, df):
    create_if_dont_exists(path)
    df.to_csv(path, index=False)


def save_json(path, env):
    create_if_dont_exists(path)

    with open(path, 'w') as file:
        file.write(json.dumps(env, indent=4))


def save_pickle_obj(path, model):
    create_if_dont_exists(path)

    with open(path, 'wb') as file:
        pickle.dump(model, file, protocol=pickle.HIGHEST_PROTOCOL)


def load_pickle_obj(path):
    if not os.path.exists(path):
        return None

    with open(path, 'rb') as file:
        learner = pickle.load(file)

    return learner


def to_file(path, text):
    create_if_dont_exists(path)

    with open(path, 'a') as f:
        f.write(text)
