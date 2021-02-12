from time import sleep


class ESTask:
    task_id = None
    running_seconds = None
    description = None
    es = None

    def __init__(self, es, task_id, running_seconds, description):
        self.es = es
        self.task_id = task_id
        self.running_seconds = running_seconds
        self.description = description

    def cancel(self, cancel_children=True, wait_for_exit=False):
        self.es.tasks.cancel(task_id=self.task_id)
        if cancel_children:
            for child in get_tasks(self.es, parent_id=self.task_id):
                self.es.tasks.cancel(task_id=child.task_id)
        if wait_for_exit:
            while any(self.task_id == t.task_id for t in get_tasks(self.es, nodes='_local')):
                sleep(10)


def get_tasks(es, nodes=None, parent_id=None):
    results = []
    node_tasks = es.tasks.list(
        detailed=True, nodes=nodes, parent_task_id=parent_id)
    for node, node_info in node_tasks['nodes'].items():
        for task_id, task_info in node_info['tasks'].items():
            results.append(ESTask(
                es, task_id, task_info['running_time_in_nanos']/1000000000, task_info['description']))
    return results
