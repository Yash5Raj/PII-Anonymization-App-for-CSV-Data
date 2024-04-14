from presidio_analyzer import BatchAnalyzerEngine, DictAnalyzerResult, PatternRecognizer, AnalyzerEngine, RecognizerRegistry
from presidio_anonymizer import BatchAnonymizerEngine, AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
import random
import hashlib
import json
import pandas as pd
import streamlit as st

def load_metadata():
    '''this function will load metadata from the JSON metadata file'''
    with open('config/metadata.json', 'r') as config_json:
        config = json.load(config_json)
        config_json.close()
    return config
    
def update_metadata(entity_metadata: dict, selected_entity: str, operation_type: str, operation_config: str, new_entity=False, remove_entity=False):
    '''this funtion is used to update the metadata loaded in the session state'''
    if new_entity:
        entity_metadata['pii_operation_metadata_dict']['Entity_Type'].append(selected_entity)
        entity_metadata['pii_operation_metadata_dict']['Operation'].append(operation_type)
        entity_metadata['pii_operation_metadata_dict']['Operation_Config'].append(operation_config)
    elif remove_entity:
        entity_metadata['pii_operation_metadata_dict']['Entity_Type'].remove(selected_entity)
        entity_metadata['pii_operation_metadata_dict']['Operation'].remove(operation_type)
        entity_metadata['pii_operation_metadata_dict']['Operation_Config'].remove(operation_config)  
    else:
        entity_metadata['pii_operation_metadata_dict']['Operation'][entity_metadata['pii_operation_metadata_dict']['Entity_Type'].index(selected_entity)] = operation_type
        entity_metadata['pii_operation_metadata_dict']['Operation_Config'][entity_metadata['pii_operation_metadata_dict']['Entity_Type'].index(selected_entity)] = operation_config
    return entity_metadata

def update_metadata_json(entity_metadata: dict, selected_entity: str, operation_type: str, operation_config: str, new_entity=False, remove_entity=False):
    '''NOTE: this function will update the physical metadata file'''
    if new_entity:
        entity_metadata['pii_operation_metadata_dict']['Entity_Type'].append(selected_entity)
        entity_metadata['pii_operation_metadata_dict']['Operation'].append(operation_type)
        entity_metadata['pii_operation_metadata_dict']['Operation_Config'].append(operation_config)
    elif remove_entity:
        entity_metadata['pii_operation_metadata_dict']['Entity_Type'].remove(selected_entity)
        entity_metadata['pii_operation_metadata_dict']['Operation'].remove(operation_type)
        entity_metadata['pii_operation_metadata_dict']['Operation_Config'].remove(operation_config)            
    else:
        entity_metadata['pii_operation_metadata_dict']['Operation'][entity_metadata['pii_operation_metadata_dict']['Entity_Type'].index(selected_entity)] = operation_type
        entity_metadata['pii_operation_metadata_dict']['Operation_Config'][entity_metadata['pii_operation_metadata_dict']['Entity_Type'].index(selected_entity)] = operation_config
    with open('config/metadata.json', 'w') as config_json:
        json.dump(entity_metadata, config_json)
        config_json.close()
    return load_metadata()

@st.cache_data(show_spinner=False)
def getPIIEntities(df: pd.core.frame.DataFrame) -> dict:
    pii_entity_metadata = {'Column': [], 'Entity': [], 'Text_Flag': []}
    for x in df.columns:
        temp_df = df[[x]].dropna().reset_index().drop(['index'], axis=1)
        # checking if the column contains 'text' data
        lst = ['text' for y in random.sample(range(1, 11), 5) if str(df[x][y]).find(' ') != -1 and len(str(df[x][y])) > 30]
        if len(lst) != 0: # column is text
            column_dict = temp_df[[x]].to_dict(orient='list')
            analyzer = AnalyzerEngine()
            batch_analyzer = BatchAnalyzerEngine(analyzer_engine=analyzer)
            batch_analyzer_result_list = list(batch_analyzer.analyze_dict(column_dict, language="en"))
            text_column_entities_list = [y.entity_type for i in batch_analyzer_result_list[0].recognizer_results if len(i) != 0 for y in i]
            text_column_entities_list_distinct = []
            for i in text_column_entities_list:
                if i not in text_column_entities_list_distinct:
                    text_column_entities_list_distinct.append(i)
            print(f"{x}: {', '.join(text_column_entities_list_distinct)}")
            pii_entity_metadata['Column'].append(x)
            pii_entity_metadata['Entity'].append(', '.join(text_column_entities_list_distinct))
            pii_entity_metadata['Text_Flag'].append(True)
        else:
            column_dict = temp_df[[x]].to_dict(orient='list')
            analyzer = AnalyzerEngine()
            batch_analyzer = BatchAnalyzerEngine(analyzer_engine=analyzer)
            batch_analyzer_result_list = list(batch_analyzer.analyze_dict(column_dict, language="en"))
            # get entity
            count_dict = {}
            for z in range(len(batch_analyzer_result_list[0].recognizer_results)):
                if len(batch_analyzer_result_list[0].recognizer_results[z]) != 0:
                    entity_type = batch_analyzer_result_list[0].recognizer_results[z][0].entity_type
                    if entity_type not in count_dict.keys():
                        count_dict[entity_type] = 1
                    else:
                        count_dict[entity_type] += 1
            if len(count_dict) != 0:
                print(f"{x}: {max(count_dict, key=count_dict.get)}")
                pii_entity_metadata['Column'].append(x)
                pii_entity_metadata['Entity'].append(max(count_dict, key=count_dict.get))
                pii_entity_metadata['Text_Flag'].append(False)
            else:
                print(f"{x}: No PII entity found.")
                pii_entity_metadata['Column'].append(x)
                pii_entity_metadata['Entity'].append('No PII entity found.')
                pii_entity_metadata['Text_Flag'].append(False)
    return pii_entity_metadata

def columnAnonymize(df: pd.core.frame.DataFrame, column_name: str, entities: str, operation_config: dict) -> pd.core.frame.DataFrame:
    # converting entities str to list
    entities = entities.split(', ')
    # initializing Anonymizer and Analyzer
    analyzer = AnalyzerEngine()
    batch_analyzer = BatchAnalyzerEngine(analyzer_engine=analyzer)
    batch_anonymizer = BatchAnonymizerEngine()
    # creating dictionary to pass to analyzer
    input_dict = df[[column_name]].to_dict(orient='list')
    # don't know why this is happening, something wierd, apprantly keys in dictionary is being reordered.
    for i, x in enumerate(operation_config['Operation']):
        if x == 'mask':
            operation_config['Operation_Config'][i]['from_end'] = str(operation_config['Operation_Config'][i]['from_end']).lower() == 'true'   

    if 'PERSON' in operation_config['Entity_Type']:
        person_operation = operation_config['Operation'][operation_config['Entity_Type'].index('PERSON')]
        person_operation_config = operation_config['Operation_Config'][operation_config['Entity_Type'].index('PERSON')]
    else:
        person_operation = 'redact'
        person_operation_config = {}  
    if 'EMAIL_ADDRESS' in operation_config['Entity_Type']:
        email_address_operation = operation_config['Operation'][operation_config['Entity_Type'].index('EMAIL_ADDRESS')]
        email_address_operation_config = operation_config['Operation_Config'][operation_config['Entity_Type'].index('EMAIL_ADDRESS')]
    else:
        email_address_operation = 'mask'
        email_address_operation_config = {'masking_char': '*', 'chars_to_mask': 100, 'from_end': True} 
    if 'IP_ADDRESS' in operation_config['Entity_Type']:
        ip_address_operation = operation_config['Operation'][operation_config['Entity_Type'].index('IP_ADDRESS')]
        ip_address_operation_config = operation_config['Operation_Config'][operation_config['Entity_Type'].index('IP_ADDRESS')]
    else:
        ip_address_operation = 'hash'
        ip_address_operation_config = {'hash_type': 'sha256'} 
    if 'URL' in operation_config['Entity_Type']:
        url_operation = operation_config['Operation'][operation_config['Entity_Type'].index('URL')]
        url_operation_config = operation_config['Operation_Config'][operation_config['Entity_Type'].index('URL')]
    else:
        url_operation = 'replace'
        url_operation_config = {'new_value': '<URL>'}   
    if 'LOCATION' in operation_config['Entity_Type']:
        location_operation = operation_config['Operation'][operation_config['Entity_Type'].index('LOCATION')]
        location_operation_config = operation_config['Operation_Config'][operation_config['Entity_Type'].index('LOCATION')]
    else:
        location_operation = 'replace'
        location_operation_config = {'new_value': '<LOCATION>'}   
    if 'PHONE_NUMBER' in operation_config['Entity_Type']:
        phone_number_operation = operation_config['Operation'][operation_config['Entity_Type'].index('PHONE_NUMBER')]
        phone_number_operation_config = operation_config['Operation_Config'][operation_config['Entity_Type'].index('PHONE_NUMBER')]
    else:
        phone_number_operation = 'replace'
        phone_number_operation_config = {'new_value': '<PHONE_NUMBER>'}   
    if 'CREDIT_CARD' in operation_config['Entity_Type']:
        credit_card_operation = operation_config['Operation'][operation_config['Entity_Type'].index('CREDIT_CARD')]
        credit_card_operation_config = operation_config['Operation_Config'][operation_config['Entity_Type'].index('CREDIT_CARD')]
    else:
        credit_card_operation = 'replace'
        credit_card_operation_config = {'new_value': '<CREDIT_CARD>'}    
    if 'DATE_TIME' in operation_config['Entity_Type']:
        date_time_operation = operation_config['Operation'][operation_config['Entity_Type'].index('DATE_TIME')]
        date_time_operation_config = operation_config['Operation_Config'][operation_config['Entity_Type'].index('DATE_TIME')]
    else:
        date_time_operation = 'replace'
        date_time_operation_config = {'new_value': '<DATE_TIME>'}    
    if 'NRP' in operation_config['Entity_Type']:
        nrp_card_operation = operation_config['Operation'][operation_config['Entity_Type'].index('NRP')]
        nrp_card_operation_config = operation_config['Operation_Config'][operation_config['Entity_Type'].index('NRP')]
    else:
        nrp_card_operation = 'replace'
        nrp_card_operation_config = {'new_value': '<NRP>'}                                                                      
    # operator configuration for anonymization operations
    operator = {
        'DEFAULT': OperatorConfig('replace', {'new_value': '<ANONYMIZE>'}),
        'PERSON': OperatorConfig(person_operation, person_operation_config),
        'EMAIL_ADDRESS': OperatorConfig(email_address_operation, email_address_operation_config),
        'IP_ADDRESS': OperatorConfig(ip_address_operation, ip_address_operation_config),
        'URL': OperatorConfig(url_operation, url_operation_config),
        'LOCATION': OperatorConfig(location_operation, location_operation_config),
        'PHONE_NUMBER': OperatorConfig(phone_number_operation, phone_number_operation_config),
        'CREDIT_CARD': OperatorConfig(credit_card_operation, credit_card_operation_config),
        'DATE_TIME': OperatorConfig(date_time_operation, date_time_operation_config),        
        'NRP': OperatorConfig(nrp_card_operation, nrp_card_operation_config)
    }
    # passing input dictionary to analyzer
    batch_analyzer_result_list = list(batch_analyzer.analyze_dict(input_dict, language="en", entities=entities))
    # passing analyzer result to anonymizer
    batch_anonymizer_result = batch_anonymizer.anonymize_dict(batch_analyzer_result_list, operators=operator)      
    anonymized_column_df = pd.DataFrame(batch_anonymizer_result)
    # replace column with anonymized data
    df[column_name] = anonymized_column_df
    return df

def columnReplace(df: pd.core.frame.DataFrame, column_name, operation_config: dict) -> pd.core.frame.DataFrame:
    column_dict = df[[column_name]].to_dict(orient='list')
    for i, x in enumerate(column_dict[column_name]):
        column_dict[column_name][i] = operation_config['new_value']
    df[column_name] = pd.DataFrame(column_dict)    
    return df
def columnRedact(df: pd.core.frame.DataFrame, column_name, operation_config: dict) -> pd.core.frame.DataFrame:
    column_dict = df[[column_name]].to_dict(orient='list')
    for i, x in enumerate(column_dict[column_name]):
        column_dict[column_name][i] = ''
    df[column_name] = pd.DataFrame(column_dict)
    return df    
def columnHash(df: pd.core.frame.DataFrame, column_name: str, operation_config: dict, salt: bool = False) -> pd.core.frame.DataFrame:
    column_dict = df[[column_name]].to_dict(orient='list')
    if operation_config['hash_type'] == 'sha256':
        column_dict[column_name] = [hashlib.sha256(x.encode()).hexdigest() for x in column_dict[column_name]]
        df[column_name] = pd.DataFrame(column_dict)
    elif operation_config['hash_type'] == 'sha512':
        column_dict[column_name] = [hashlib.sha512(x.encode()).hexdigest() for x in column_dict[column_name]]
        df[column_name] = pd.DataFrame(column_dict)
    elif operation_config['hash_type'] == 'md5':
        column_dict[column_name] = [hashlib.md5(x.encode()).hexdigest() for x in column_dict[column_name]]
        df[column_name] = pd.DataFrame(column_dict)        
    return df 
def columnMask(df: pd.core.frame.DataFrame, column_name: str, operation_config: dict) -> pd.core.frame.DataFrame:
    operation_config['from_end'] = str(operation_config['from_end']).lower() == 'true'                                    
    column_dict = df[[column_name]].to_dict(orient='list')
    if operation_config['from_end']:
        for i, x in enumerate(column_dict[column_name]):
            column_dict[column_name][i] = str(column_dict[column_name][i])[:max(len(str(column_dict[column_name][i])) - operation_config['chars_to_mask'], 0)] + len(str(column_dict[column_name][i])[:operation_config['chars_to_mask']]) * operation_config['masking_char']
    else:
        for i, x in enumerate(column_dict[column_name]):
            column_dict[column_name][i] = operation_config['masking_char'] * len(str(column_dict[column_name][i])[:operation_config['chars_to_mask']]) + str(column_dict[column_name][i])[operation_config['chars_to_mask']:]
    df[column_name] = pd.DataFrame(column_dict)
    return df

def anonymizeData(df: pd.core.frame.DataFrame, filtered_pii_entities_dict: dict, pii_operation_metadata_dict: dict) -> pd.core.frame.DataFrame:
    for i, x in enumerate(filtered_pii_entities_dict['Column']):
        if filtered_pii_entities_dict['Text_Flag'][i]:
            df = columnAnonymize(df, x, filtered_pii_entities_dict['Entity'][i], pii_operation_metadata_dict)
        elif filtered_pii_entities_dict['Entity'][i] in pii_operation_metadata_dict['Entity_Type']:
            # getting anonymization operation associated with the entity
            operation = pii_operation_metadata_dict['Operation'][pii_operation_metadata_dict['Entity_Type'].index(filtered_pii_entities_dict['Entity'][i])]
            if operation == 'replace':
                df = columnReplace(df, x, pii_operation_metadata_dict['Operation_Config'][pii_operation_metadata_dict['Operation'].index(operation)])
            if operation == 'redact':
                df = columnRedact(df, x, pii_operation_metadata_dict['Operation_Config'][pii_operation_metadata_dict['Operation'].index(operation)])
            if operation == 'hash':
                df = columnHash(df, x, pii_operation_metadata_dict['Operation_Config'][pii_operation_metadata_dict['Operation'].index(operation)])
            if operation == 'mask':
                df = columnMask(df, x, pii_operation_metadata_dict['Operation_Config'][pii_operation_metadata_dict['Operation'].index(operation)])
        else:
            print(f'Default operation to be performed for {x}: REPLACE')
            print('calling columnReplace')
            df = columnReplace(df, x, '<ANONYMIZED>')  
    return df