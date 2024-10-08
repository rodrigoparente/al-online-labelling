# python imports
import os
import sys

# local imports
from steps import get_specialist_name
from steps import creating_initial_pool_test
from steps import initial_test_labelling
from steps import active_learning_labelling
from steps import super_learning_labelling


INITIAL_DATASET_SIZE = 20
TEST_DATASET_SIZE = 60
ACTIVE_LEARNING_DATASET_SIZE = 100
RANDOM_SELECTED_DATASET_SIZE = 100


if __name__ == '__main__':

    base_dir = os.path.dirname(os.path.abspath(__file__))
    results_path = os.path.join(base_dir, 'results', '')

    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        # if the application is run as a bundle, the PyInstaller
        # sets the application path into variable called _MEIPASS
        base_dir = sys._MEIPASS
        results_path = os.path.join(
            os.path.dirname(sys.executable), 'results', '')

    os.environ['base_dir'] = base_dir
    os.environ['results_path'] = results_path

    name = get_specialist_name()

    print('\n - Creating pool, initial, and test datasets...')
    creating_initial_pool_test(
        initial_size=INITIAL_DATASET_SIZE, test_size=TEST_DATASET_SIZE)

    print(' - Starting labelling process of initial and test datasets...')
    initial_test_labelling(name)

    print(' - Starting active learning labelling...')
    active_learning_labelling(name,
                              model_name='gb',
                              query_strategy='uncertainty-sampling',
                              number_queries=ACTIVE_LEARNING_DATASET_SIZE)

    print(' - Starting supervised learning labelling...')
    super_learning_labelling(name,
                             model_name='gb',
                             number_queries=RANDOM_SELECTED_DATASET_SIZE)

    input('\nLabelling process finished! Press any key to exit.')
