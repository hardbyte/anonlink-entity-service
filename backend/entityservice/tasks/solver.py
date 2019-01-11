from array import array
from anonlink.solving import greedy_solve

from entityservice.object_store import connect_to_object_store
from entityservice.async_worker import celery, logger
from entityservice.settings import Config as config
from entityservice.tasks.base_task import TracedTask
from entityservice.tasks.permutation import save_and_permute
from entityservice.utils import similarity_matrix_from_csv_bytes


@celery.task(base=TracedTask, ignore_result=True, args_as_tags=('project_id', 'run_id'))
def solver_task(similarity_scores_filename, project_id, run_id, lenf1, lenf2, parent_span):
    log = logger.bind(pid=project_id, run_id=run_id)
    mc = connect_to_object_store()
    solver_task.span.log_kv({'lenf1': lenf1, 'lenf2': lenf2, 'filename': similarity_scores_filename})
    score_file = mc.get_object(config.MINIO_BUCKET, similarity_scores_filename)
    log.debug("Creating python sparse matrix from bytes data")
    sparse_matrix = similarity_matrix_from_csv_bytes(score_file.data)

    log.info("Morphing sparse similarity scores into required format")
    # Iterable of (score, ind1, ind2)
    # but want individual lists of scores, ds_ids, record_ids
    # No this isn't the most ideal way to do it, however we are planning on updating to use
    # more of the anonlink's newer api when we implement multiparty solver.
    scores = array("d")
    rec0_ids = array("I")
    rec1_ids = array("I")

    for (score, rec0, rec1) in sparse_matrix:
        scores.append(score)
        rec0_ids.append(rec0)
        rec1_ids.append(rec1)
    dset_is0 = array("I", [0]*len(scores))
    dset_is1 = array("I", [1]*len(scores))

    log.info("Solving the mapping from similarity matrix")
    groups = greedy_solve((scores, (dset_is0, dset_is1), (rec0_ids, rec1_ids)))

    # Now format results as a dict mapping index in record 0 to index in record 1
    mapping = {}
    for group in groups:
        if len(group) == 2:
            a, b = group[0], group[1]
            if b[0] == 0:
                a, b = b, a
            mapping[str(a[1])] = str(b[1])
        else:
            log.warning(f"Ignoring group of size ${len(group)}")

    log.info("Mapping has been computed")

    res = {
        "mapping": mapping,
        "lenf1": lenf1,
        "lenf2": lenf2
    }
    save_and_permute.delay(res, project_id, run_id, solver_task.get_serialized_span())
