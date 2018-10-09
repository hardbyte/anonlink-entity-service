import celery

from entityservice.errors import DBResourceMissing
import psycopg2
from structlog import get_logger
from entityservice.tracing import create_tracer
from opentracing.propagation import Format

import time
from entityservice.errors import DBResourceMissing
import psycopg2
from structlog import get_logger

logger = get_logger()


class BaseTask(celery.Task):
    """Abstract base class for all tasks in Entity Service"""

    abstract = True
    throws = (DBResourceMissing, psycopg2.IntegrityError)

    def on_retry(self, exc, task_id, args, kwargs, einfo):
        """Log the exceptions to some central logging system at retry."""
        #todo captureException(exc)
        logger.warning("Task {} is retrying after a '{}' exception".format(
            task_id, exc.__class__.__name__))

        super(BaseTask, self).on_retry(exc, task_id, args, kwargs, einfo)

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Log the exceptions"""
        logger.info("An exception '{}' was raised in a task".format(exc.__class__.__name__))

        if isinstance(exc, (DBResourceMissing, psycopg2.IntegrityError)):
            logger.info("Task was running when a resource was deleted, or db was inconsistent. Ignoring")
            # Note it will still be logged by celery
            # http://docs.celeryproject.org/en/master/userguide/tasks.html#Task.throws

        else:
            logger.exception(f"Unexpected exception raised in task {task_id}", exc_info=einfo)
            super(BaseTask, self).on_failure(exc, task_id, args, kwargs, einfo)


class TracedTask(BaseTask):
    """
    wraps an opentracing span around a task execution.
    Adds two properties to a task:
        - tracer: the task-local tracer
        - span: the wrapper span
    thus you can do things like:
        task.tracer.create_span('thus_span', child_of=task.span) as thus_span:
        or
        task.span.log_kv()
    But beware, this is not quite like standard opentracing principles, as
    this is not a global tracer (opentracing.tracer will not work!!)
    """
    _tracer = None
    _span = None

    @property
    def tracer(self):
        if self._tracer is None:
            self._tracer = create_tracer('anonlink-worker')
        return self._tracer

    @property
    def span(self):
        return self._span

    def get_serialized_span(self):
        serialized_span = {}
        self.tracer.inject(self.span, Format.TEXT_MAP, serialized_span)
        return serialized_span

    def __call__(self, *args, **kwargs):
        args_dict = dict(zip(self.run.__code__.co_varnames, args))
        args_dict.update(kwargs)
        parent = args_dict.get(getattr(self, 'parent_span_arg', 'parent_span'), None)
        try:
            parent = self.tracer.extract(Format.TEXT_MAP, parent)
        except:
            pass
        if parent is None:
            print('bugger, parent is None')
        with self.tracer.start_span(getattr(self, 'span_name', self.name), child_of=parent) as wrapper_span:
            self._span = wrapper_span
            for span_tag in getattr(self, 'args_as_tags', []):
                wrapper_span.set_tag(span_tag, args_dict.get(span_tag, None))
            return super(TracedTask, self).__call__(*args, **kwargs)

    def after_return(self, status, retval, task_id, args, kwargs, einfo):
        time.sleep(2) # jaeger bug
        #print('closing task tracer')
        self.tracer.close()
        self._tracer = None
        return super(TracedTask, self).after_return(status, retval, task_id, args, kwargs, einfo)
