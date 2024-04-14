import streamlit as st
import pandas as pd
from utility.anonymization_functions import *


if 'metadata' not in st.session_state.keys():
    st.session_state['metadata'] = load_metadata()

st.sidebar.title('🕵️PII Anonymization App')
st.header("Anonymize CSV data📅")
st.sidebar.markdown('''---''')
if len(st.session_state['metadata']['pii_operation_metadata_dict']['Entity_Type']) < 2:
    st.warning('⚠️Please populate the Entity Metadata before proceeding.')
    st.stop() # if not entities are there nothing should be executing
else:
    st.sidebar.markdown('👤Selected PII Entities & Operations:')
    edit_toggle = st.sidebar.toggle(label='Edit✏️')
    if edit_toggle:
        entity_selectbox = st.sidebar.selectbox('Select Entity:', st.session_state['metadata']['pii_operation_metadata_dict']['Entity_Type'], index=1)
        if entity_selectbox == 'ADD NEW +':
            new_entity_selectbox = st.sidebar.selectbox('Select New Entity', options=[x for x in st.session_state['metadata']['base_pii_entities_list'] if x not in st.session_state['metadata']['pii_operation_metadata_dict']['Entity_Type'][1:]])
            operation_selectbox = st.sidebar.selectbox('Select Operation Type:', ['replace', 'redact', 'hash', 'mask'], help='❗Will use same operation for all the **_Entites_**, inputed by user.')
            if operation_selectbox == 'replace' and operation_selectbox is not None:
                new_value_text_box = st.sidebar.text_input(value= '<ANONYMIZED>', label='Enter value to replace PII data.')
                operation={'new_value':new_value_text_box}
            if operation_selectbox == 'redact' and operation_selectbox is not None:
                operation={}
            if operation_selectbox == 'mask' and operation_selectbox is not None:
                masking_char_selectbox = st.sidebar.selectbox('Select the Masking Character:', ('*', '#'))
                number_of_char_text_box = st.sidebar.text_input(value=20, label='Enter length of chars to mask:')
                from_end_check_box = st.sidebar.radio(label='Mask from end of char:', options=['True', 'False'])
                operation={'masking_char':masking_char_selectbox, 'chars_to_mask': int(number_of_char_text_box), 'from_end':str(from_end_check_box)}
            if operation_selectbox == 'hash' and operation_selectbox is not None:
                hash_type_selectbox = st.sidebar.selectbox(label='Select Hash Type:', options=('sha256', 'sha512', 'md5'))
                operation={'hash_type': hash_type_selectbox}
        else:        
            entity_operations_list = ['replace', 'redact', 'hash', 'mask']
            operation_selectbox = st.sidebar.selectbox('Select Operation Type:', entity_operations_list, index=entity_operations_list.index(st.session_state['metadata']['pii_operation_metadata_dict']['Operation'][st.session_state['metadata']['pii_operation_metadata_dict']['Entity_Type'].index(entity_selectbox)]), help='❗Will use same operation for all the **_Entites_**, inputed by user.')
            if operation_selectbox == 'replace' and operation_selectbox is not None:
                new_value_text_box = st.sidebar.text_input(value= '<ANONYMIZED>', label='Enter value to replace PII data.')
                operation={'new_value':new_value_text_box}
            if operation_selectbox == 'redact' and operation_selectbox is not None:
                operation={}
            if operation_selectbox == 'mask' and operation_selectbox is not None:
                masking_char_selectbox = st.sidebar.selectbox('Select the Masking Character:', ('*', '#'))
                number_of_char_text_box = st.sidebar.text_input(value=20, label='Enter length of chars to mask:')
                from_end_check_box = st.sidebar.radio(label='Mask from end of char:', options=['True', 'False'])
                operation={'masking_char':masking_char_selectbox, 'chars_to_mask': int(number_of_char_text_box), 'from_end':str(from_end_check_box)}
            if operation_selectbox == 'hash' and operation_selectbox is not None:
                hash_type_selectbox = st.sidebar.selectbox(label='Select Hash Type:', options=('sha256', 'sha512', 'md5'))
                operation={'hash_type': hash_type_selectbox}
            remove_entity_checkbox = st.sidebar.checkbox('🗑️')
        if st.sidebar.button('Update Metadata🔃', type='primary'):
            if 'new_entity_selectbox' in locals().keys() and len(new_entity_selectbox) != 0:
                st.session_state['metadata'] = update_metadata(st.session_state['metadata'], new_entity_selectbox, operation_selectbox, operation, new_entity=True)
            else:
                st.session_state['metadata'] = update_metadata(st.session_state['metadata'], entity_selectbox, operation_selectbox, operation, remove_entity=remove_entity_checkbox)
    st.sidebar.dataframe(pd.DataFrame(st.session_state['metadata']['pii_operation_metadata_dict']).iloc[1:, :], hide_index=True)
st.sidebar.markdown('''---''')    

source_type_selectbox = st.sidebar.selectbox(label='Source Type:', options=['Local System', 'ADLS'])
if source_type_selectbox == 'Local System':
    upload_csv_file = st.sidebar.file_uploader("Upload CSV file")
    if upload_csv_file is not None:
        if upload_csv_file.name.split('.')[-1] != 'csv':
            e = RuntimeError('Currently any file other than CSV type is not supported.')
            st.exception(e)
        else:
            # reading the csv file
            input_df = pd.read_csv(upload_csv_file, encoding='unicode_escape')
            output_df = input_df
            input_df = input_df.head(100)
            # showing the input data
            st.write('⬇️Input Data:')
            st.dataframe(input_df, hide_index=True)
        if st.sidebar.button('🔬Analyze Data for PII'):
            if  edit_toggle != True:
                with st.spinner('Analyzing Input Data for PII...'):
                    st.session_state['found_pii_entities_dict'] = getPIIEntities(input_df)        
                if len(st.session_state['found_pii_entities_dict']['Entity']) != 0:
                    st.session_state['filtered_pii_entities_dict'] = {'Column': [], 'Entity': [], 'Text_Flag': []}
                    for i, x in enumerate(st.session_state['found_pii_entities_dict']['Entity']):
                        if st.session_state['found_pii_entities_dict']['Text_Flag'][i]:
                            y = [i for i in x.split(', ') if i in st.session_state['metadata']['pii_operation_metadata_dict']['Entity_Type'][1:]]
                            st.session_state['filtered_pii_entities_dict']['Column'].append(st.session_state['found_pii_entities_dict']['Column'][i])
                            st.session_state['filtered_pii_entities_dict']['Entity'].append(', '.join(y))
                            st.session_state['filtered_pii_entities_dict']['Text_Flag'].append(st.session_state['found_pii_entities_dict']['Text_Flag'][i])
                        else:
                            if x in st.session_state['metadata']['pii_operation_metadata_dict']['Entity_Type'][1:]:
                                st.session_state['filtered_pii_entities_dict']['Column'].append(st.session_state['found_pii_entities_dict']['Column'][i])
                                st.session_state['filtered_pii_entities_dict']['Entity'].append(x)
                                st.session_state['filtered_pii_entities_dict']['Text_Flag'].append(st.session_state['found_pii_entities_dict']['Text_Flag'][i])
                    entity_df = pd.DataFrame(st.session_state['filtered_pii_entities_dict']).filter(['Column', 'Entity'])
                    with st.expander('Found PII entities🔎', expanded=True):
                        st.write(f'Total Columns: **{len(input_df.columns)}**')
                        st.write(f"Total Columns Containing PII data for _Selected Entities_: **{len(st.session_state['filtered_pii_entities_dict']['Column'])}**")
                        st.dataframe(entity_df, hide_index=True)
                else:
                    st.success('No PII Entities found ✅!')
            else:
                st.warning('⚠️PII metadata is in *Edit* mode!')      
        if st.sidebar.button('🔎Anonymized PII Data', type='primary'):
            if 'found_pii_entities_dict' in st.session_state.keys() and len(st.session_state['found_pii_entities_dict']['Entity']) != 0:
                st.sidebar.markdown('''---''')
                st.sidebar.markdown('Anonymizing data for below columns and respective PII entities')
                st.sidebar.dataframe(pd.DataFrame(st.session_state['filtered_pii_entities_dict']).filter(['Column', 'Entity']), hide_index=True)
                with st.spinner('Anonymizing the PII...'):
                    pii_operation_metadata_dict = {
                    'Entity_Type': st.session_state['metadata']['pii_operation_metadata_dict']['Entity_Type'][1:],
                    'Operation': st.session_state['metadata']['pii_operation_metadata_dict']['Operation'][1:],
                    'Operation_Config': st.session_state['metadata']['pii_operation_metadata_dict']['Operation_Config'][1:]
                    }

                    output_df = anonymizeData(output_df, st.session_state['filtered_pii_entities_dict'], pii_operation_metadata_dict)
                st.write('⬆️Output Data:')
                st.dataframe(output_df, hide_index=True)
            else:
                st.warning('⚠️Please analyze data for PII entities first.')         