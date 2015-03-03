def sort_list(linkList):
    

def query():
    return_list =[]
    for link in links:
        if link.submitter_id==62443:
            return_list.append([link.url, link.submitted_time])
    return return_list

print query()