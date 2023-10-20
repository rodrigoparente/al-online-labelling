# python imports
import os
import sys

# local imports
from steps import get_specialist_name
from steps import creating_initial_pool_test
from steps import initial_test_labelling
from steps import active_learning_labelling
from steps import super_learning_labelling


if __name__ == '__main__':

    base_dir = os.path.dirname(os.path.abspath(__file__))
    results_path = os.path.join(base_dir, 'AL_ONLINE_LABELLING_RESULTS', '')

    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        # if the application is run as a bundle, the PyInstaller
        # sets the application path into variable called _MEIPASS
        base_dir = sys._MEIPASS
        results_path = os.path.join(
            os.path.dirname(sys.executable), 'AL_ONLINE_LABELLING_RESULTS', '')

    os.environ['base_dir'] = base_dir
    os.environ['results_path'] = results_path

    name = get_specialist_name()

    print('\n - Creating pool, initial, and test datasets...')
    creating_initial_pool_test(initial_size=20, test_size=60)

    print(' - Starting labelling process of initial and test datasets...')
    initial_test_labelling(name)

    print(' - Starting active learning labelling...')
    active_learning_labelling(name,
                              model_name='gb',
                              query_strategy='uncertainty-sampling',
                              number_queries=100)

    print(' - Starting supervised learning labelling...')
    super_learning_labelling(name,
                             model_name='gb',
                             number_queries=100)

    input('\nLabelling process finished! Press any key to exit.')
