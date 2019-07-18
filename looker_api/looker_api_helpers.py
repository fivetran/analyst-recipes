# Copyright (C) 2019 Fivetran

import requests
import json

def generate_auth_token():
    """Generates an access token for the Looker API that can be passed in the required authorization header.
    These tokens expire in an hour"""
    data = {
        'client_id': 'xxxxxx', # get id client and secret
        'client_secret': 'xxxxxx'
    }
    auth_token = requests.post('https://xxxxx.looker.com:19999/api/3.1/login', data=data) # get company api url
    return auth_token.json().get('access_token')


HEADERS = {
    'Authorization': 'token {}'.format(generate_auth_token())
}

URL = 'https://fivetran.looker.com:19999/api/3.1/'


def get_dashboard(dashboard_id):
    dashboard = requests.get('{}dashboards/{}'.format(URL, dashboard_id), headers=HEADERS)
    return dashboard.json()


def get_all_dashboards():
    dashboards = requests.get(URL + 'dashboards', headers=HEADERS)
    return dashboards.json()


def get_look(look_id):
    look = requests.get('{}looks/{}'.format(URL, look_id), headers=HEADERS)
    return look.json()


def get_all_looks():
    looks = requests.get(URL + 'looks', headers=HEADERS)
    return looks.json()


def get_query(query_id):
    query = requests.get('{}queries/{}'.format(URL, query_id), headers=HEADERS)
    return query.json()


def get_merge_query(merge_query_id):
    merge_query = requests.get(URL + 'merge_queries/{}'.format(merge_query_id), headers=HEADERS)
    return merge_query.json()


def get_all_schedules_plans():
    scheduled_plans = requests.get('{}{}'.format(URL, "scheduled_plans"), headers=HEADERS, params={'all_users': 'true'})
    return scheduled_plans.json()


def get_user_id_mapping():
    """Returns a mapping of looker user id to user email"""
    all_users = requests.get(URL + 'users', headers=HEADERS).json()
    user_id_look_up = {}
    for user in all_users:
        user_id_look_up[user["id"]] = user["email"]
    return user_id_look_up


def match_text(lookup_str, text_to_match, match_whole_text, case_sensitive=False):
    """Checks to see if the lookup string matches the text_to_match either partially or exactly.
    """
    if text_to_match and lookup_str:
        if case_sensitive:
            text_to_match = str(text_to_match)
            lookup_str = str(lookup_str)
        else:
            text_to_match = str(text_to_match).lower()
            lookup_str = str(lookup_str).lower()
        if match_whole_text:
            return lookup_str == text_to_match
        else:
            return lookup_str in text_to_match
    return False


def find_matching_text_in_query_fields(query, lookup_str, match_whole_text, case_sensitive=False):
    """Loops through the list of fields in a query and checks if the provided text input matches the field
    text partially or wholly

    Args:
        query (dict): looker query
        lookup_str (str): text to match, e.g. "quarter"
        match_whole_text (boolean): if true, it will check if there's a match to the whole string
        case_sensitive (boolean): if true the match will be case sensitive
    """
    query_fields = query.get('fields')
    matching_query_fields = []
    if isinstance(query_fields, list):
        for field in query_fields:
            if match_text(lookup_str, field, match_whole_text, case_sensitive):
                matching_query_fields.append(field)
    return matching_query_fields


def find_matching_text_in_filter_fields(query, lookup_str, match_whole_text, case_sensitive=False):
    """Loops through the list of filters in a query to check if the provided text matches either the filter field

    Filters are stored as a dictionary in the query
    e.g. {'opportunities.created_date_quarter': 'this quarter'}

    Args:
        query (dict): looker query
        lookup_str (str): text to match, e.g. "quarter"
        match_whole_text (boolean): if true, it will check if there's a match to the whole string
        case_sensitive (boolean): if true the match will be case sensitive
    """
    filters = query.get('filters')
    matching_filter_fields = []
    if isinstance(filters, dict):
        for field, value in filters.items():
            if match_text(lookup_str, field, match_whole_text, case_sensitive):
                # return the value filter value for reference
                matching_filter_fields.append({'field': field, 'filter_value': value})
    return matching_filter_fields


def find_matching_text_in_filter_values(query, lookup_str, match_whole_text, case_sensitive=False):
    """Loops through the list of filters in a query to check if the provided text matches either the filter value

    Filters are stored as a dictionary in the query
    e.g. {'opportunities.created_date_quarter': 'this quarter'}

    Args:

        query (dict): looker query
        lookup_str (str): text to match, e.g. "quarter"
        match_whole_text (boolean): if true, it will check if there's a match to the whole string
        case_sensitive (boolean): if true the match will be case sensitive
    """
    filters = query.get('filters')
    matching_filter_values = []
    if isinstance(filters, dict):
        for field, filter_value in filters.items():
            if match_text(lookup_str, filter_value, match_whole_text, case_sensitive):
                # return the value filter value for reference
                matching_filter_values.append({'field': field, 'filter_value': filter_value})
    return matching_filter_values


def find_matching_text_in_filter_expression(query, lookup_str, match_whole_text, case_sensitive=False):
    """Checks the filter expression in a query to see if the lookup_str matches.

    Filter expression example: '${opportunities.created_fiscal_quarter} > ${accounts.created_date_fiscal_quarter}'
    Args:

        query (dict): looker query
        lookup_str (str): text to match, e.g. "quarter"
        match_whole_text (boolean): if true, it will check if there's a match to the whole string
        case_sensitive (boolean): if true the match will be case sensitive
    """
    filter_expression = query.get('filter_expression')
    if filter_expression:
        if match_text(lookup_str, filter_expression, match_whole_text, case_sensitive):
            return filter_expression


# test_query = get_query(164570)
# test_match = find_matching_text_in_filter_expression(test_query, 'quarter', False)
# print("Hello")

def find_matching_text_in_query_table_calcs(query, lookup_str, match_whole_text, case_sensitive=False):
    """Loops through the dynamic fields (table calculations, custom dimensions, custom measures) in a query and
    checks if the provided text input matches the field text partially or wholly

    Args:
        query (dict): looker query
        lookup_str (str): text to match, e.g. "quarter"
        match_whole_text (boolean): if true, it will check if there's a match to the whole string
        case_sensitive (boolean): if true the match will be case sensitive
    """
    query_dynamic_fields = query.get('dynamic_fields')
    matching_query_fields = []
    if query_dynamic_fields:
        # dynamic fields which should be lists of dics are currently being returned as a string,
        # need to transform the string to list
        if isinstance(query_dynamic_fields, str):
            query_dynamic_fields = json.loads(query_dynamic_fields)
        if isinstance(query_dynamic_fields, list):
            for dynamic_field in query_dynamic_fields:
                expression = dynamic_field.get('expression')
                label = dynamic_field.get('label')
                if match_text(lookup_str, expression, match_whole_text, case_sensitive):
                    matching_query_fields.append({'label': label, 'expression': expression})
        # should probably
    return matching_query_fields


def find_matching_text_in_dashboard_filter_fields(dashboard_filters, lookup_str, match_whole_text, case_sensitive=False):
    """Loops through the list of dashboard filters to see if the provided text matches the
    dashboard filter dimension (field)

    Args:
        dashboard_filters (list): list of dicts containing dashboard filters. E.g.
        [{'id': 1,
          'name': 'Account Owner',
          'dimension': 'account.owner_name',
          'default_value': 'Christine'
         },
         {'id': 2,
          'name': 'Account Status',
          'dimension': 'account.account_status',
          'default_value': 'Active'
         }]
        lookup_str (str): text to match, e.g. "quarter"
        match_whole_text (boolean): if true, it will check if there's a match to the whole string
        case_sensitive (boolean): if true the match will be case sensitive
        dashboard_details


    """
    matching_filter_fields = []
    if isinstance(dashboard_filters, list):
        for dashboard_filter in dashboard_filters:
            field = dashboard_filter.get('dimension')
            value = dashboard_filter.get('default_value')
            if match_text(lookup_str, field, match_whole_text, case_sensitive):
                matching_filter_fields.append({'field': field, 'filter_value': value})
    return matching_filter_fields


def find_matching_text_in_dashboard_filter_values(dashboard_filters, lookup_str, match_whole_text, case_sensitive=False):
    """Loops through the list of dashboard filters to see if the provided text matches the
    dashboard filter value (default value)

    Args:
        dashboard_filters (list): list of dicts containing dashboard filters. E.g.
        [{'id': 1,
          'name': 'Account Owner',
          'dimension': 'account.owner_name',
          'default_value': 'Christine'
         },
         {'id': 2,
          'name': 'Account Status',
          'dimension': 'account.account_status',
          'default_value': 'Active'
         }]
        lookup_str (str): text to match, e.g. "quarter"
        match_whole_text (boolean): if true, it will check if there's a match to the whole string
        case_sensitive (boolean): if true the match will be case sensitive


    """
    matching_filter_values = []
    if isinstance(dashboard_filters, list):
        for dashboard_filter in dashboard_filters:
            field = dashboard_filter.get('dimension')
            value = dashboard_filter.get('default_value')
            if match_text(lookup_str, value, match_whole_text, case_sensitive):
                matching_filter_values.append({'field': field, 'filter_value': value})
    return matching_filter_values


def parse_merge_queries(merge_result_id):
    """For a merge query, returns the list of fields used to merge the source queries,
     the ids of the source queries and the table calculation expressions

    Args:
        merge_result_id: merge result id of the dashboard element referencing a merge query
    """
    merge_query = get_merge_query(merge_result_id)
    merge_fields = []
    merge_query_ids = []
    for source_query in merge_query["source_queries"]:
        query_id = source_query.get("query_id")
        if query_id:
            query = get_query(query_id)
            merge_query_ids.append({'query_id': query_id, 'query': query})
        query_merge_fields = source_query.get("merge_fields")
        if query_merge_fields:
            for merge_field_set in query_merge_fields:
                merge_fields.append(merge_field_set["source_field_name"])
                merge_fields.append(merge_field_set["field_name"])
    if merge_fields:
        merge_fields = list(set(merge_fields))

    # get table calculation expressions
    table_calcs = []
    query_dynamic_fields = merge_query.get('dynamic_fields')
    # dynamic fields which should be lists of dics are currently being returned as a string,
    # need to transform the string to list
    if query_dynamic_fields and isinstance(query_dynamic_fields, str):
        query_dynamic_fields = json.loads(query_dynamic_fields)
        if isinstance(query_dynamic_fields, list):
            for dynamic_field in query_dynamic_fields:
                table_calcs.append({'label': dynamic_field.get('label'), 'expression': dynamic_field.get('expression')})
    return {"merge_fields": merge_fields, "merge_query_ids": merge_query_ids, "table_calcs": table_calcs}


def parse_looks():
    """Parses looks and returns the associated query ids
    """
    all_looks = get_all_looks()
    parsed_looks = []
    user_id_mapping = get_user_id_mapping()
    for found_look in all_looks:  # [all_looks[88]]: #TODO REMOVE THE FILTER AFTER TESTING!
        if not found_look.get('deleted'):
            look = get_look(found_look['id'])
            try:
                look_id = look.get('id')
                query_id = look.get("query_id")
                user_id = look.get("user_id")
                user_email = user_id_mapping[user_id]
                look_title = look.get('title')
                if query_id:
                    query = get_query(query_id)
                    parsed_looks.append({'look_id': look_id,
                                         'query_id': query_id,
                                         'query': query,
                                         'look_title': look_title,
                                         "user_id": user_id,
                                         "user_email": user_email
                                         })
            except Exception as e:
                print("Exception raised when looping through looks:")
                print(e)
    return parsed_looks


def parse_dashboard_elements():
    """Parse dashboards and dashboard tiles (looks excluded) and returns:
        associated queries
        source queries for merged queries
        merged query merge field
        dashboard filters

    """
    all_dashboards = json.loads(requests.get(URL + 'dashboards', headers=HEADERS).text)
    parsed_dashboards = {"tiles": [], "merged_query_tiles": [], "dashboard_level_filters": []}
    user_id_mapping = get_user_id_mapping()
    for dashboard in all_dashboards:  # [all_dashboards[67]]: #all_dashboards: #TODO FOR TESTING DELETE THIS!!!!!!!!!!!!!!!!!!!
        dashboard_id = dashboard['id']
        dashboard_detail = json.loads(
            requests.get('{}dashboards/{}'.format(URL, dashboard_id), headers=HEADERS).text)
        if dashboard_detail.get('deleted') != None:
            if not dashboard_detail['deleted']:
                try:
                    # step 1: check for matches in dashboard level filters
                    user_id = dashboard_detail.get('user_id')
                    user_email = user_id_mapping[user_id]
                    dashboard_title = dashboard_detail.get('title')
                    dashboard_filters = dashboard_detail.get('dashboard_filters')
                    dashboard_elements = dashboard_detail.get('dashboard_elements')
                    if dashboard_filters:
                        parsed_dashboards["dashboard_level_filters"].append({"dashboard_id": dashboard_id,
                                                                             "dashboard_title": dashboard_title,
                                                                             "dashboard_filters": dashboard_filters,
                                                                             "user_id": user_id,
                                                                             "user_email": user_email})
                    if dashboard_elements:
                        for element in dashboard_elements:
                            dashboard_element_id = element.get('id')
                            query = element.get('query')
                            merge_result_id = element.get('merge_result_id')
                            element_title = element.get('title')
                            element_id = dashboard_element_id
                            # non-look-based dashboard tile
                            if query:
                                query_id = query.get('id')
                                element_type = 'dashboard {} tile'.format(dashboard_id)
                                parsed_dashboards["tiles"].append({"dashboard_id": dashboard_id,
                                                                   "dashboard_title": dashboard_title,
                                                                   "element_id": element_id,
                                                                   "element_title": element_title,
                                                                   "element_type": element_type,
                                                                   "query_id": query_id,
                                                                   "query": query,
                                                                   "user_id": user_id,
                                                                   "user_email": user_email})
                            # dashboard tile derived from merge result
                            if merge_result_id:
                                element_type = 'dashboard {} tile (merge_query)'.format(dashboard_id)
                                merge_query_data = parse_merge_queries(merge_result_id)
                                merge_fields = merge_query_data["merge_fields"]
                                merge_source_query_ids = merge_query_data["merge_query_ids"]
                                merge_query_table_calcs = merge_query_data["table_calcs"]
                                parsed_dashboards["merged_query_tiles"].append({"dashboard_id": dashboard_id,
                                                                                "dashboard_title": dashboard_title,
                                                                                "element_id": element_id,
                                                                                "element_title": element_title,
                                                                                "element_type": element_type,
                                                                                "merge_source_query_ids": merge_source_query_ids,
                                                                                "merge_fields": merge_fields,
                                                                                "merge_query_table_calcs": merge_query_table_calcs,
                                                                                "merge_result_id": merge_result_id,
                                                                                "user_id": user_id,
                                                                                "user_email": user_email})
                except Exception as e:
                    print(e)

        else:
            print("Dashboard {} unable to get dashboard details".format(dashboard_id))
    return parsed_dashboards


def update_query(query, old_text, new_text):
    """Replaces text in a query and returns an updated query dictionary"""

    # In order to create a new query, read_only fields need to be removed
    # Filter config also needs to be removed otherwise it will override the filter options in the ui
    read_only_fields = ["id", "client_id", "slug", "share_url", "url", "expanded_share_url", "has_table_calculations",
                        "can", "filter_config"]
    for field in read_only_fields:
        if field in query:
            query.pop(field)
    query_dumped = json.dumps(query)
    query_updated = query_dumped.replace(old_text, new_text)
    new_query = json.loads(query_updated)
    return new_query


def create_new_query(query):
    """Creates a new query in Looker from the input query dictionary"""
    headers = HEADERS
    headers['content-type'] = 'application/json'
    try:
        new_query_request = requests.post(URL + 'queries', headers=headers, data=json.dumps(query))
        new_query_response = new_query_request.json()
        new_query_id = new_query_response.get("id")
        if new_query_id:
            new_query = get_query(new_query_id)
            return new_query
        else:
            raise Exception("Failed to create new query: {}".format(new_query_response.get('message')))
    except Exception as e:
        print("Exception with creating a new query")
        print(e)
        print(query)


def update_look_dashboard_element_query_id(element_type, element_id, new_query_id):
    """Replaces the query_id value for a look or dashboard element with the new query id

    Args:
        element_type: looks or dashboard_elements

    Returns the query id of the element it has updated.
    """
    headers = HEADERS
    headers['content-type'] = 'application/json'
    try:
        update_request = requests.patch('{}{}/{}'.format(URL, element_type, element_id), headers=headers,
                                        data=json.dumps({'query_id': new_query_id}))
        # verify updated query_id
        get_updated_dashboard_element = requests.get('{}{}/{}'.format(URL, element_type, element_id), headers=headers)
        updated_element = get_updated_dashboard_element.json()
        updated_query_id = updated_element.get("query_id")
        if str(updated_query_id) != str(new_query_id):
            raise Exception("Failed to update query id {} with new query id {}".format(updated_query_id, new_query_id))
        return updated_query_id
    except Exception as e:
        print("Exception with update query id method for {} {} and new query id {}".format(element_type, element_id,
                                                                                           new_query_id))
        print(e)
        
