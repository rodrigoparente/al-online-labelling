# python imports
import sys
import random
from ast import literal_eval

# third-party imports
import pandas as pd
import numpy as np

from sklearn.preprocessing import OneHotEncoder
from sklearn.preprocessing import MultiLabelBinarizer

from tabulate import tabulate

# filtering messages to error
import warnings
warnings.filterwarnings('ignore')


def prep_data(data):
    # droping unused columns
    data = data.drop(columns=['cve_id', 'base_severity', 'audience_normalized'])

    # encoding dataset
    data = encode_data(data)

    if 'label' in data.columns:
        X = data.drop(columns='label').to_numpy()
        y = data['label'].to_numpy()

        return X, y

    return data.to_numpy(), None


def encode_data(data):
    # casting dates to days
    columns = ['cve_published_date', 'exploit_published_date']
    formats = ['%m/%d/%Y', '%Y-%m-%d']

    for column, format in zip(columns, formats):
        data[column] = pd.to_datetime(data[column], format=format)
        data[column] = (pd.to_datetime('today') - pd.to_datetime(data[column])).dt.days

        # replacing nan with 0
        data.loc[data[column].isnull(), column] = 0
        data[column] = data[column].astype(int)

    # replacing nan values in exploit
    # and audience columns to 0
    columns = ['exploit_count', 'audience']
    for column in columns:
        data.loc[data[column].isnull(), column] = 0
        data[column] = data[column].astype(int)

    # replacing nan values in epss column
    data.loc[data['epss'].isnull(), 'epss'] = 0.0

    # replacing nan values in google_trend and google_interest column
    data.loc[data['google_trend'].isnull(), 'google_trend'] = 'none'
    data.loc[data['google_interest'].isnull(), 'google_interest'] = 0.0

    # replacing values in advisory_publised_date column
    data.loc[~data['advisory_published_date'].isnull(), 'advisory_published_date'] = 1
    data.loc[data['advisory_published_date'].isnull(), 'advisory_published_date'] = 0

    data.rename(columns={'advisory_published_date': 'security_advisory'}, inplace=True)
    data['security_advisory'] = data['security_advisory'].astype(int)

    # casting upper values to lower
    columns =\
        ['confidentiality_impact', 'integrity_impact', 'availability_impact',
         'google_trend', 'topology', 'asset_type', 'environment']
    for column in columns:
        data[column] = data[column].str.lower()

    # replacing attack_type space with underscore
    data['attack_type'].replace(', ', ',', regex=True, inplace=True)
    data['attack_type'].replace('-', '_', regex=True, inplace=True)
    data['attack_type'].replace(' ', '_', regex=True, inplace=True)

    # replacing attack_type nan value
    data.loc[data['attack_type'].isnull(), 'attack_type'] = "['none']"

    # casting attack_type string to array
    data['attack_type'] = data['attack_type'].apply(literal_eval)

    # manually encoding columns value
    data['topology'].replace({'local': 0, 'dmz': 1}, inplace=True)
    data['asset_type'].replace({'workstation': 0, 'server': 1}, inplace=True)
    data['environment'].replace({'development': 0, 'production': 1}, inplace=True)

    # one-hot-encoding data
    ohe = OneHotEncoder(sparse=False, dtype=int)

    columns = ['part', 'vendor', 'confidentiality_impact',
               'integrity_impact', 'availability_impact', 'google_trend']

    encoder_vars_array = ohe.fit_transform(data[columns])

    # create object for the feature names using the categorical variables
    encoder_feature_names = ohe.get_feature_names_out(columns)

    # create a dataframe to hold the one hot encoded variables
    encoder_vars_df = pd.DataFrame(encoder_vars_array, columns=encoder_feature_names)

    # adding possible missing features
    ohe_features = [
        'part_application', 'part_hardware', 'part_operating_system',
        'vendor_adobe', 'vendor_apple', 'vendor_cisco', 'vendor_debian',
        'vendor_google', 'vendor_ibm', 'vendor_fedoraproject', 'vendor_microsoft',
        'vendor_oracle', 'vendor_other', 'vendor_redhat',
        'confidentiality_impact_high', 'confidentiality_impact_low',
        'confidentiality_impact_none', 'integrity_impact_high',
        'integrity_impact_low', 'integrity_impact_none',
        'availability_impact_high', 'availability_impact_low',
        'availability_impact_none', 'google_trend_decreasing',
        'google_trend_increasing', 'google_trend_none',
        'google_trend_steady']

    missing_ohe_features = list(set(ohe_features).difference(encoder_feature_names))

    n_rows = data.shape[0]
    df_dict = dict()

    for column in missing_ohe_features:
        df_dict.setdefault(column, np.zeros(n_rows, dtype=int))

    # concatenate the new dataframe back to the original input variables dataframe
    data = pd.concat([
        data.reset_index(drop=True),
        encoder_vars_df.reset_index(drop=True),
        pd.DataFrame(df_dict).reset_index(drop=True)], axis=1)

    # drop the original columns
    data.drop(columns, axis=1, inplace=True)

    # multi-hot-encoding
    mlb = MultiLabelBinarizer()
    mlb.fit(data['attack_type'])

    # creating new columns name
    new_col_names = [f'attack_type_{name}' for name in mlb.classes_]

    # create new dataFrame with transformed/one-hot encoded
    attacks = pd.DataFrame(mlb.fit_transform(data['attack_type']), columns=new_col_names)

    # concat encoded data with original dataframe
    data = pd.concat([data.reset_index(drop=True), attacks.reset_index(drop=True)], axis=1)

    # drop the original column
    data.drop('attack_type', axis=1, inplace=True)

    # adding possible missing attack types
    types_of_attack =\
        ['none', 'remote_code_execution', 'arbitrary_code_execution', 'tampering',
         'denial_of_service', 'spoofing', 'defense_in_depth', 'elevation_of_privilege',
         'security_feature_bypass', 'information_disclosure', 'xss', 'memory_leak',
         'sql_injection', 'zero_day', 'proof_of_concepts']

    # creating new columns
    missing_attack_types = list(set(types_of_attack).difference(mlb.classes_))
    missing_columns = [f'attack_type_{name}' for name in missing_attack_types]

    n_rows = data.shape[0]
    df_dict = dict()

    # prep data
    for column in missing_columns:
        df_dict.setdefault(column, np.zeros(n_rows, dtype=int))

    # concatenating to original dataset
    data = pd.concat([data, pd.DataFrame(df_dict)], axis=1)

    # sorting columns
    data = data[sorted(data.columns)]

    return data


def assign_ctx_info(vulns):

    # asset context
    asset_ctx = [
        ['DMZ', 'SERVER', 'PRODUCTION', 0, 1, 0],
        ['DMZ', 'SERVER', 'PRODUCTION', 0, 0, 0],
        ['LOCAL', 'SERVER', 'PRODUCTION', 1, 1, 1],
        ['LOCAL', 'SERVER', 'PRODUCTION', 1, 1, 0],
        ['LOCAL', 'SERVER', 'PRODUCTION', 1, 0, 1],
        ['LOCAL', 'SERVER', 'PRODUCTION', 1, 0, 0],
        ['LOCAL', 'SERVER', 'PRODUCTION', 0, 1, 1],
        ['LOCAL', 'SERVER', 'PRODUCTION', 0, 1, 0],
        ['LOCAL', 'SERVER', 'PRODUCTION', 0, 0, 1],
        ['LOCAL', 'SERVER', 'PRODUCTION', 0, 0, 0],
        ['LOCAL', 'SERVER', 'DEVELOPMENT', 1, 1, 0],
        ['LOCAL', 'SERVER', 'DEVELOPMENT', 1, 0, 0],
        ['LOCAL', 'SERVER', 'DEVELOPMENT', 0, 1, 0],
        ['LOCAL', 'SERVER', 'DEVELOPMENT', 0, 0, 0],
        ['LOCAL', 'WORKSTATION', 'PRODUCTION', 1, 1, 1],
        ['LOCAL', 'WORKSTATION', 'PRODUCTION', 1, 1, 0],
        ['LOCAL', 'WORKSTATION', 'PRODUCTION', 1, 0, 1],
        ['LOCAL', 'WORKSTATION', 'PRODUCTION', 1, 0, 0],
        ['LOCAL', 'WORKSTATION', 'PRODUCTION', 0, 1, 1],
        ['LOCAL', 'WORKSTATION', 'PRODUCTION', 0, 1, 0],
        ['LOCAL', 'WORKSTATION', 'PRODUCTION', 0, 0, 1],
        ['LOCAL', 'WORKSTATION', 'PRODUCTION', 0, 0, 0],
        ['LOCAL', 'WORKSTATION', 'DEVELOPMENT', 0, 1, 0],
        ['LOCAL', 'WORKSTATION', 'DEVELOPMENT', 0, 0, 0],
    ]

    asset_ctx_cols = [
        'topology', 'asset_type', 'environment',
        'sensitive_data', 'end_of_life', 'critical_asset']

    # columns of the final dataset
    output_columns = vulns.columns.tolist() + asset_ctx_cols

    # list to hold output values (vulns + ctx info)
    values_list = [[] for _ in range(len(output_columns))]

    # randomly assigning a context to the selected vuln
    for row in zip(*vulns.to_dict("list").values()):
        row_list = list(row) + random.choice(asset_ctx)
        for index, value in enumerate(row_list):
            values_list[index].append(value)

    # formating output list
    results = dict()
    for column, values in zip(output_columns, values_list):
        results.setdefault(column, values)

    # generating pandas df
    return pd.DataFrame(results, columns=output_columns)


def append_row(df, row, label):
    values = row.values.tolist() + [label]
    columns = row.index.tolist() + ['label']

    row = pd.DataFrame([values], columns=columns)
    return pd.concat([df, row])


def print_row(row):

    print('\nVulnerability Characteristics')
    print('-' * 100)

    print(tabulate([
        ['platform', 'vendor', 'base_score',
         'cve_published_date', 'update_available'],
        [row.part, row.vendor, row.base_score,
         row.cve_published_date, row.update_available]
    ], headers='firstrow', tablefmt='rounded_outline'))

    print(tabulate([
        ['confidentiality_impact', 'integrity_impact', 'availability_impact'],
        [row.confidentiality_impact, row.integrity_impact, row.availability_impact]
    ], headers='firstrow', tablefmt='rounded_outline'))

    print('\nThreat Intelligence Information')
    print('-' * 100)

    print(tabulate([
        ['mitre_top_25', 'owasp_top_10', 'epss',
         'exploit_count', 'exploit_published_date'],
        [row.mitre_top_25, row.owasp_top_10, row.epss,
         row.exploit_count, row.exploit_published_date]
    ], headers='firstrow', tablefmt='rounded_outline'))

    print(tabulate([
        ['advisory_published_date', 'audience',
         'google_trend', 'google_interest', 'attack_type'],
        [row.advisory_published_date, row.audience_normalized,
         row.google_trend, row.google_interest, row.attack_type]
    ], headers='firstrow', tablefmt='rounded_outline'))

    print('\nContext Characteristics')
    print('-' * 100)

    print(tabulate([
        ['topology', 'asset_type', 'environment', 'sensitive_data',
         'end_of_life', 'critical_asset'],
        [row.topology, row.asset_type, row.environment, row.sensitive_data,
         row.end_of_life, row.critical_asset]
    ], headers='firstrow', tablefmt='rounded_outline'))


def get_answer(row):
    print_row(row)

    print('\nType the risk of the vulnerability.')
    print('Options:\n (0) LOW (1) MODERATE '
          '(2) IMPORTANT (3) CRITICAL (q) Quit\n')

    while True:

        label = input('>> ')

        if label == 'q':
            sys.exit()
        elif label.isnumeric() and 0 <= int(label) <= 3:
            return label
        else:
            print('\033[1A\033[J', end='')  # erase last line of the console
            continue
