# python imports
import os
import sys

# third-party imports
import pandas as pd
import numpy as np

from sklearn_extra.cluster import KMedoids
from sklearn.preprocessing import StandardScaler
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import precision_score
from sklearn.metrics import recall_score
from sklearn.metrics import f1_score
from sklearn.utils import shuffle

from modAL.models import ActiveLearner

# local imports
from classifiers import get_estimator
from classifiers import get_query_strategy

from data import prep_data
from data import get_answer
from data import append_row
from data import encode_data
from data import assign_ctx_info

from file import save_df
from file import save_pickle_obj
from file import to_file
from file import create_if_dont_exists

from utils import abs_base_path
from utils import abs_results_path
from utils import clear_window

from constants import TOP_10_VENDORS


def get_specialist_name():

    results_path = abs_results_path()
    create_if_dont_exists(results_path)

    dirs = os.listdir(results_path)

    names = list()
    options = ''

    for index, dir in enumerate(dirs):
        names.append(dir)
        options += f'  ({index}) {dir}\n'

    finished = False
    specialist = ''

    while not finished:
        clear_window()

        if len(dirs) > 0:
            print('Continue working from where you left by choosing one of'
                  ' the following options, or type a new username:')

            print(f'Options: \n{options}')
        else:
            print('Type a new username:\n')

        name = input('>> ')

        if name == '':
            continue
        elif name.isnumeric():
            index = int(name)
            if index < len(names):
                finished = True
                specialist = names[index]
        else:
            finished = True
            specialist = name.replace(' ', '-').lower()

    clear_window()

    return specialist


def creating_initial_pool_test(initial_size, test_size):

    initial_path = abs_base_path('datasets/initial.csv')
    pool_path = abs_base_path('datasets/pool.csv')
    test_path = abs_base_path('datasets/test.csv')
    vulns_path = abs_base_path('datasets/vulns.csv')

    if not os.path.isfile(initial_path) \
        or not os.path.isfile(pool_path) \
            or not os.path.isfile(test_path):

        # loading vulnerabilities

        vulns = pd.read_csv(vulns_path, low_memory=False)

        # preparing vulnerabilities dataset

        vulns = vulns.loc[vulns['cvss_type'] == 3.0]

        vulns = vulns[[
            'cve_id', 'part', 'vendor', 'base_score', 'base_severity', 'confidentiality_impact',
            'integrity_impact', 'availability_impact', 'cve_published_date', 'update_available',
            'mitre_top_25', 'owasp_top_10', 'exploit_count', 'epss', 'exploit_published_date',
            'advisory_published_date', 'attack_type', 'audience', 'audience_normalized',
            'google_trend', 'google_interest'
        ]]

        def rename_part(part):
            if part[0] == 'o':
                return 'operating_system'
            elif part[0] == 'h':
                return 'hardware'
            elif part[0] == 'a':
                return 'application'

        vulns['part'] = vulns['part'].apply(eval)
        vulns['part'] = vulns['part'].apply(lambda value: rename_part(value))

        vulns['vendor'] = vulns['vendor'].apply(eval)
        vulns['vendor'] = vulns['vendor'].apply(
            lambda val: val[0] if val[0] in TOP_10_VENDORS else 'other')

        vulns = vulns.sample(frac=1)

        # assigning context data to vulnerabilities

        vulns = assign_ctx_info(vulns)

        # selecting pool and test dataset

        pool = vulns.iloc[test_size:, :]
        test = vulns.iloc[:test_size, :]

        # selecting initial dataset

        pool_encoded = pool.sample(frac=0.30)
        pool_encoded = pool_encoded.drop(
            columns=['cve_id', 'base_severity', 'audience_normalized'])

        pool_encoded = encode_data(pool_encoded).to_numpy()

        kmedoids = KMedoids(n_clusters=initial_size)
        kmedoids.fit(StandardScaler().fit_transform(pool_encoded))

        initial_idx = kmedoids.medoid_indices_

        initial = pool.iloc[initial_idx]
        pool = pool.loc[~pool.index.isin(initial_idx)]

        # saving datasets

        initial.to_csv(initial_path, index=False)
        pool.to_csv(pool_path, index=False)
        test.to_csv(test_path, index=False)


def initial_test_labelling(specialist_name):

    filenames = ['initial', 'test']

    for name in filenames:
        input_csv = pd.read_csv(abs_base_path(f'datasets/{name}.csv'), low_memory=False)
        max_size = input_csv.shape[0]

        output_csv = pd.DataFrame()
        output_csv_path = abs_results_path(f'{specialist_name}/datasets/{name}-labelled.csv')

        if os.path.isfile(output_csv_path):
            output_csv = pd.read_csv(output_csv_path, low_memory=False)

        # check if all vulnerabilities were labelled
        if output_csv.shape[0] == input_csv.shape[0]:
            continue

        if not output_csv.empty:
            input_csv = input_csv.loc[~input_csv['cve_id'].isin(output_csv['cve_id'].tolist())]

        for _, row in input_csv.iterrows():
            clear_window()

            print('-' * 100)
            print(f'{name.upper()} DATASET LABELLING ({output_csv.shape[0] + 1}/{max_size})')
            print('-' * 100)

            label = get_answer(row)

            output_csv = append_row(output_csv, row, label)
            save_df(output_csv_path, output_csv)


def active_learning_labelling(
        specialist_name, model_name, query_strategy, number_queries):

    pool_csv_path = abs_base_path('datasets/pool.csv')
    initial_csv_path = abs_results_path(f'{specialist_name}/datasets/initial-labelled.csv')
    test_csv_path = abs_results_path(f'{specialist_name}/datasets/test-labelled.csv')
    active_labelled_csv_path = abs_results_path(f'{specialist_name}/datasets/active-labelled.csv')

    if not os.path.isfile(initial_csv_path) or \
            not os.path.isfile(test_csv_path):
        sys.exit()

    # loading datasets

    pool = pd.read_csv(pool_csv_path, low_memory=False)
    initial = pd.read_csv(initial_csv_path, low_memory=False)
    test = pd.read_csv(test_csv_path, low_memory=False)
    active_labelled = pd.DataFrame()

    if os.path.isfile(active_labelled_csv_path):
        active_labelled = pd.read_csv(active_labelled_csv_path, low_memory=False)

    # check if all vulnerabilities were labelled

    if active_labelled.shape[0] == number_queries:
        return

    # remove labelled vulnerabilities from pool

    if not active_labelled.empty:
        pool = pool.loc[~pool['cve_id'].isin(active_labelled['cve_id'].tolist())]

    # preping data

    X_pool, _ = prep_data(pool)
    X_initial, y_initial = prep_data(initial)
    X_test, y_test = prep_data(test)

    X_active_labelled = np.ndarray(shape=(0, X_pool.shape[1]))
    y_active_labelled = np.ndarray(shape=(0,))

    if not active_labelled.empty:
        X_active_labelled, y_active_labelled = prep_data(active_labelled)

    # running algorithm

    X_selected = np.r_[X_initial, X_active_labelled]
    y_selected = np.r_[y_initial, y_active_labelled]

    n_queries_left = number_queries - len(X_active_labelled)

    def get_learner(model_name, query_strategy, X_train, y_train):

        arr = y_train.tolist()
        arr = [arr.count(x) for x in [0., 1., 2., 3.]]
        split = False if min(arr) < 5 else True

        if split:
            calibrated = CalibratedClassifierCV(
                estimator=get_estimator(model_name), method='isotonic', cv=5)
            calibrated.fit(X_train, y_train)

            learner = ActiveLearner(
                estimator=calibrated,
                query_strategy=get_query_strategy(query_strategy))
        else:
            learner = ActiveLearner(
                estimator=get_estimator(model_name),
                query_strategy=get_query_strategy(query_strategy),
                X_training=X_train, y_training=y_train)

        return learner

    for _ in range(n_queries_left):

        # select an instance using active learning to be labelled
        learner = get_learner(model_name, query_strategy, X_selected, y_selected)
        query_idx, query_inst = learner.query(X_pool)

        clear_window()

        print('-' * 100)
        print(f'ACTIVE LEARNING LABELLING ({active_labelled.shape[0] + 1}/{number_queries})')
        print('-' * 100)

        # asking specialist to label the instance
        row = pool.iloc[query_idx].squeeze()
        label = get_answer(row)

        print('\nprocessing... it may take a while.')

        active_labelled = append_row(active_labelled, row, label)
        save_df(active_labelled_csv_path, active_labelled)

        X_selected = np.append(X_selected, query_inst, axis=0)
        y_selected = np.append(y_selected, np.array([int(label)], dtype=int), axis=0)

        X_pool = np.delete(X_pool, query_idx, axis=0)

        # training a model to obtain metrics
        learner = get_learner(model_name, query_strategy, X_selected, y_selected)
        y_pred = learner.predict(X_test)

        accuracy = learner.score(X_test, y_test)
        precision = precision_score(y_test, y_pred, average='weighted')
        recall = recall_score(y_test, y_pred, average='weighted')
        f1 = f1_score(y_test, y_pred, average='weighted')

        stats = f'{accuracy} {precision} {recall} {f1}\n'
        stats_path = abs_results_path(f'{specialist_name}/active-stats.txt')
        to_file(stats_path, stats)

        number = len(active_labelled)
        model_path = abs_results_path(f'{specialist_name}/models/active/model-{number}.pickle')
        save_pickle_obj(model_path, learner)


def super_learning_labelling(
        specialist_name, model_name, number_queries):

    pool_csv_path = abs_base_path('datasets/pool.csv')
    initial_csv_path = abs_results_path(f'{specialist_name}/datasets/initial-labelled.csv')
    test_csv_path = abs_results_path(f'{specialist_name}/datasets/test-labelled.csv')
    super_labelled_csv_path = abs_results_path(f'{specialist_name}/datasets/super-labelled.csv')

    if not os.path.isfile(initial_csv_path) or \
            not os.path.isfile(test_csv_path):
        sys.exit()

    # loading datasets

    pool = pd.read_csv(pool_csv_path, low_memory=False)
    initial = pd.read_csv(initial_csv_path, low_memory=False)
    test = pd.read_csv(test_csv_path, low_memory=False)
    super_labelled = pd.DataFrame()

    if os.path.isfile(super_labelled_csv_path):
        super_labelled = pd.read_csv(super_labelled_csv_path, low_memory=False)

    # check if all vulnerabilities were labelled

    if super_labelled.shape[0] == number_queries:
        return

    # remove labelled vulnerabilities from pool

    if not super_labelled.empty:
        pool = pool.loc[~pool['cve_id'].isin(super_labelled['cve_id'].tolist())]

    # preping data

    X_pool, _ = prep_data(pool)
    X_initial, y_initial = prep_data(initial)
    X_test, y_test = prep_data(test)

    X_super_labelled = np.ndarray(shape=(0, X_pool.shape[1]))
    y_super_labelled = np.ndarray(shape=(0,))

    if not super_labelled.empty:
        X_super_labelled, y_super_labelled = prep_data(super_labelled)

    # running algorithm

    X_selected = np.r_[X_initial, X_super_labelled]
    y_selected = np.r_[y_initial, y_super_labelled]

    n_queries_left = number_queries - len(X_super_labelled)

    for _ in range(n_queries_left):

        # select random item and append to X_train
        query_idx = np.random.randint(len(X_pool))
        query_idx = np.array([query_idx])

        clear_window()

        print('-' * 100)
        print(f'RANDOM LEARNING LABELLING ({super_labelled.shape[0] + 1}/{number_queries})')
        print('-' * 100)

        row = pool.iloc[query_idx].squeeze()
        label = get_answer(row)

        super_labelled = append_row(super_labelled, row, label)
        save_df(super_labelled_csv_path, super_labelled)

        X_selected = np.append(X_selected, X_pool[query_idx], axis=0)
        y_selected = np.append(y_selected, np.array([int(label)], dtype=int), axis=0)

        X_pool = np.delete(X_pool, query_idx, axis=0)

        X_selected, y_selected = shuffle(X_selected, y_selected)

        learner = get_estimator(model_name)
        learner.fit(X_selected, y_selected)

        y_pred = learner.predict(X_test)

        accuracy = learner.score(X_test, y_test)
        precision = precision_score(y_test, y_pred, average='weighted')
        recall = recall_score(y_test, y_pred, average='weighted')
        f1 = f1_score(y_test, y_pred, average='weighted')

        stats = f'{accuracy} {precision} {recall} {f1}\n'
        stats_path = abs_results_path(f'{specialist_name}/super-stats.txt')
        to_file(stats_path, stats)

        number = len(super_labelled)
        model_path = abs_results_path(f'{specialist_name}/models/super/model-{number}.pickle')
        save_pickle_obj(model_path, learner)
