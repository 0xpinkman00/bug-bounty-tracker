import {useState} from 'react';
import {ArrowLeft,ArrowRight,ArrowUpRight,Boxes,CheckCircle2,Download,Globe2,History,Pause,Play,RefreshCw,Square} from 'lucide-react';
import {Link,useParams} from 'react-router-dom';
import {api,formatDate,sourceLabel,useApi,type Page,type Program,type Run,type Source} from './api';
import {Badge,Empty,ErrorBanner,Loading,PageTitle,Panel} from './ui';

const descriptions:Record<string,string>={immunefi:'Web3 bounty programs, smart contracts, and protocol scope.',hackenproof:'Security programs and in-scope targets across HackenProof.'};
function statusTone(status:string):'green'|'amber'|'red'|'blue'{return status==='completed'?'green':status==='failed'||status==='stopped'?'red':status==='running'?'blue':'amber'}
function isActive(run:Run|null|undefined){return run?.status==='queued'||run?.status==='running'||run?.status==='pausing'||run?.status==='paused'||run?.status==='stopping'}

type ControlProps={name:string;run:Run|null;onChanged:()=>Promise<unknown>;compact?:boolean};
function ScrapeControls({name,run,onChanged,compact=false}:ControlProps){
  const [pending,setPending]=useState(false),[error,setError]=useState('');
  async function act(action:'start'|'pause'|'resume'|'stop'){
    setPending(true);setError('');
    try{const path=action==='start'?`/sources/${name}/sync`:`/source-syncs/${run?.id}/${action}`;await api(path,{method:'POST'});await onChanged()}
    catch(err){setError(err instanceof Error?err.message:'Could not update scrape')}
    finally{setPending(false)}
  }
  return <div className={'scrape-control-group '+(compact?'scrape-compact':'')}>
    <div className="scrape-buttons">
      {!isActive(run)&&<button className="button button-primary" disabled={pending} onClick={()=>void act('start')}><Play size={15}/>{pending?'Starting...':'Start scrape'}</button>}
      {(run?.status==='queued'||run?.status==='running')&&<button className="button button-secondary" disabled={pending} onClick={()=>void act('pause')}><Pause size={15}/>Pause</button>}
      {run?.status==='paused'&&<button className="button button-primary" disabled={pending} onClick={()=>void act('resume')}><Play size={15}/>Resume</button>}
      {(run?.status==='queued'||run?.status==='running'||run?.status==='pausing'||run?.status==='paused')&&<button className="button button-danger" disabled={pending} onClick={()=>void act('stop')}><Square size={14}/>Stop</button>}
      {run?.status==='pausing'&&<span className="control-pending"><RefreshCw size={14} className="spin"/> Pausing after current program</span>}
      {run?.status==='stopping'&&<span className="control-pending"><RefreshCw size={14} className="spin"/> Stopping after current program</span>}
    </div>
    {error&&<div className="control-error">{error}</div>}
  </div>
}

export function Sources(){
  const {data,error,loading,reload}=useApi<{items:Source[]}>('/sources',5000);
  return <><PageTitle eyebrow="DISCOVERY" title="Sources" description="Choose one platform at a time to discover new bounty programs and scope changes."/>
    {error&&<ErrorBanner message={error}/>}
    <div className="source-cards">{loading?<Loading/>:data?.items.map(source=><section className="source-card" key={source.name}>
      <Link className="source-card-link" to={'/sources/'+source.name}>
        <div className="source-card-top"><div className="source-card-icon"><Globe2 size={24}/></div><ArrowUpRight size={19}/></div>
        <div className="eyebrow">BOUNTY SOURCE</div><h2>{sourceLabel[source.name]||source.name}</h2><p>{descriptions[source.name]}</p>
      </Link>
      <div className="source-card-bottom"><div><strong>{source.program_count}</strong><span>tracked programs</span></div><div>{source.latest_run?<Badge tone={statusTone(source.latest_run.status)}>{source.latest_run.status}</Badge>:<Badge>Never scraped</Badge>}</div></div>
      <ScrapeControls name={source.name} run={source.latest_run} onChanged={reload} compact/>
    </section>)}</div>
    <Panel title="How discovery works" subtitle="Scrapes run only when you start them"><div className="steps-grid"><div><span>01</span><h3>Choose a source</h3><p>Select Immunefi or HackenProof from the cards above.</p></div><div><span>02</span><h3>Control the scrape</h3><p>Pause, resume, or stop a run as programs are processed.</p></div><div><span>03</span><h3>Review the signals</h3><p>New programs and scope changes appear in your activity feed.</p></div></div></Panel>
  </>
}

export function SourceDetail(){
  const {name=''}=useParams();
  const {data:source,error,loading,reload}=useApi<Source>('/sources/'+name,5000);
  const {data:programs}=useApi<Page<Program>>('/programs?platform='+name+'&limit=8',10000);
  if(loading)return <Loading/>;
  if(error)return <ErrorBanner message={error}/>;
  if(!source)return null;
  const run=source.latest_run;
  return <><Link className="back-link" to="/sources"><ArrowLeft size={16}/> Sources</Link>
    <div className="detail-hero"><div className="detail-icon detail-purple"><Globe2 size={28}/></div><div><div className="eyebrow">DISCOVERY SOURCE</div><h1>{sourceLabel[name]||name}</h1><p className="detail-description">{descriptions[name]}</p></div><ScrapeControls name={name} run={run} onChanged={reload}/></div>
    <div className="detail-stats"><div><span>Tracked programs</span><strong>{source.program_count}</strong></div><div><span>Discovered last run</span><strong>{run?.discovered_count??'—'}</strong></div><div><span>New last run</span><strong>{run?.created_count??'—'}</strong></div><div><span>Last scrape</span><strong>{formatDate(run?.created_at,true)}</strong></div></div>
    <div className="detail-grid"><div className="detail-main"><Panel title="Current scrape" subtitle="Progress updates automatically every few seconds" action={run&&<Badge tone={statusTone(run.status)}>{run.status}</Badge>}>{run?<>
      <div className="progress-summary"><div><strong>{run.processed_count}</strong><span>of {run.discovered_count} programs processed</span></div><span>{run.discovered_count?Math.round(run.processed_count/run.discovered_count*100):0}%</span></div>
      <div className="progress-track"><div style={{width:`${run.discovered_count?Math.min(100,run.processed_count/run.discovered_count*100):0}%`}}/></div>
      <div className="run-metrics"><div><CheckCircle2 size={18}/><strong>{run.created_count}</strong><span>new</span></div><div><RefreshCw size={18}/><strong>{run.updated_count}</strong><span>updated</span></div><div><History size={18}/><strong>{run.error_count}</strong><span>errors</span></div></div>
      {run.last_error&&<div className="error-banner">{run.last_error}</div>}
      {(run.status==='pausing'||run.status==='stopping')&&<p className="muted-note">The current program will finish before the scrape {run.status==='pausing'?'pauses':'stops'}.</p>}
      <p className="muted-note">Started {formatDate(run.started_at||run.created_at)}{run.completed_at&&<> · Finished {formatDate(run.completed_at)}</>}</p>
    </>:<Empty title="No scrapes yet" description="Start a scrape to discover programs from this source."/>}</Panel>
    <Panel title="Tracked programs" subtitle="Recently added to your workspace" action={<Link className="text-link" to={'/programs?platform='+name}>View all <ArrowRight size={15}/></Link>}>{programs?.items.length?<div className="stack-list">{programs.items.map(program=><Link className="stack-row stack-link" to={'/programs/'+program.id} key={program.id}><span className="stack-icon"><Boxes size={17}/></span><div><strong>{program.name}</strong><span>{program.max_bounty||'Bounty unspecified'}</span></div><ArrowUpRight size={16}/></Link>)}</div>:<Empty title="No programs yet" description="Programs will appear here after your first successful scrape."/>}</Panel></div>
    <div className="detail-side"><Panel title="Scrape history" subtitle="Your most recent runs">{source.runs?.length?<div className="run-history">{source.runs.map(item=><div className="run-history-row" key={item.id}><div><Badge tone={statusTone(item.status)}>{item.status}</Badge><strong>{formatDate(item.created_at,true)}</strong></div><span>{item.created_count} new · {item.updated_count} updated · {item.error_count} errors</span></div>)}</div>:<Empty title="No history yet"/>}</Panel><Panel title="What gets collected"><div className="collection-list"><div><Download size={18}/><span>Program profiles and rewards</span></div><div><Boxes size={18}/><span>Assets in scope</span></div><div><Globe2 size={18}/><span>Linked GitHub repositories</span></div><div><History size={18}/><span>Changes from earlier scrapes</span></div></div></Panel></div></div>
  </>
}
