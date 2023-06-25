# third-party imports
from modAL.uncertainty import margin_sampling
from modAL.uncertainty import entropy_sampling
from modAL.uncertainty import uncertainty_sampling

from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier


def get_estimator(name):
    if name == 'rf':
        return RandomForestClassifier()
    elif name == 'gb':
        return GradientBoostingClassifier()
    elif name == 'lr':
        return LogisticRegression(penalty='none')
    elif name == 'svc':
        return SVC(probability=True)
    elif name == 'mlp':
        return MLPClassifier()


def get_query_strategy(name):
    if name == 'entropy-sampling':
        return entropy_sampling
    elif name == 'margin-sampling':
        return margin_sampling
    elif name == 'uncertainty-sampling':
        return uncertainty_sampling
