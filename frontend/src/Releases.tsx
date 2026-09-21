import {useState} from 'react';
import {ArrowUpRight,Tag} from 'lucide-react';
import {Link} from 'react-router-dom';
import {formatDate,useApi,type Page,type Release,type ReleasePollRun} from './api';
import {Badge,Empty,ErrorBanner,Loading,PageTitle,Pagination,Panel} from './ui';

export function Releases(){
  const [offset,setOffset]=useState(0);
  const {data,error,loading}=useApi<Page<Release>>('/releases?offset='+offset+'&limit=25');
  const {data:run,error:runError,loading:runLoading}=useApi<ReleasePollRun|null>('/releases/latest-run',15000);
  return <>
    <PageTitle eyebrow="VERSION HISTORY" title="Releases" description="Every published GitHub release from the repositories you monitor."/>
    {runError&&<ErrorBanner message={runError}/>}
    <Panel title="Latest release check" subtitle={run?`${run.checked_count} of ${run.total_repositories} repositories checked · ${run.new_release_count} new releases`:'Daily GitHub release poll at 9:00 p.m.'} className="table-panel">
      {runLoading?<Loading/>:run?<>
        <div className="release-run-summary">
          <Badge tone={run.status==='completed'?'green':run.status==='running'?'blue':'amber'}>{run.status.replaceAll('_',' ')}</Badge>
          <span>Started {formatDate(run.started_at)}</span>
          {run.completed_at&&<span>Finished {formatDate(run.completed_at)}</span>}
          {run.error_count>0&&<span>{run.error_count} errors</span>}
          {run.notification_status&&run.notification_status!=='pending'&&<span>Ubuntu notification: {run.notification_status}</span>}
        </div>
        {run.repositories.length?<div className="data-table-wrap"><table className="data-table"><thead><tr><th>Repository checked</th><th>GitHub releases</th><th>Found in this run</th></tr></thead><tbody>{run.repositories.map(entry=><tr key={entry.repository_id}>
          <td><Link className="table-title" to={'/repositories/'+entry.repository_id}>{entry.repository}</Link></td>
          <td className="muted-cell">{entry.status==='checked'?entry.fetched:'Failed'}</td>
          <td>{entry.error?<span className="release-run-error">{entry.error}</span>:entry.new_releases.length?<div className="release-run-found">{entry.new_releases.map(release=><a key={release.id} href={release.url} target="_blank" rel="noreferrer">{release.tag}{release.name&&release.name!==release.tag?` · ${release.name}`:''} <ArrowUpRight size={13}/></a>)}</div>:<span className="muted-cell">No new releases</span>}</td>
        </tr>)}</tbody></table></div>:<Empty title="No repositories checked yet" description={run.status==='running'?'The daily check is starting.':'Add repositories to include them in the daily check.'}/>}
      </>:<Empty title="No release check yet" description="The first run will appear here after the 9:00 p.m. cron job."/>}
    </Panel>
    {error&&<ErrorBanner message={error}/>}
    <Panel title="Release history" subtitle={`${data?.total??0} releases tracked`} className="table-panel">{loading?<Loading/>:data?.items.length?<div className="data-table-wrap"><table className="data-table"><thead><tr><th>Release</th><th>Repository</th><th>Published</th><th></th></tr></thead><tbody>{data.items.map(release=><tr key={release.id}><td><div className="table-primary"><span className="table-icon table-icon-green"><Tag size={17}/></span><div><strong>{release.name||release.tag}</strong><div><Badge tone="green">{release.tag}</Badge></div></div></div></td><td><Link to={'/repositories/'+release.repository_id}>{release.repository_name||`Repository #${release.repository_id}`}</Link></td><td className="muted-cell">{formatDate(release.published_at)}</td><td><a className="icon-button" href={release.release_url} target="_blank" rel="noreferrer" aria-label="Open release on GitHub"><ArrowUpRight size={17}/></a></td></tr>)}</tbody></table></div>:<Empty title="No releases recorded" description="Releases appear after the daily release check."/>}</Panel>
    <Pagination total={data?.total??0} offset={offset} setOffset={setOffset}/>
  </>
}
