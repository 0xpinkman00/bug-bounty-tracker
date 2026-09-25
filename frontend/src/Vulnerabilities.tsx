import {useEffect,useState} from 'react';
import {ArrowLeft,ArrowUpRight,Bug,ChevronLeft,ChevronRight,ExternalLink,GitPullRequest,Pencil,Plus,Search,Trash2,X} from 'lucide-react';
import {Link,useNavigate,useParams,useSearchParams} from 'react-router-dom';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import {api,formatDate,useApi,type Page,type Program,type ReportSection,type Repository,type VulnerabilityReport} from './api';
import {Badge,Empty,ErrorBanner,Loading,PageTitle,Pagination,Panel,TextLink} from './ui';

const severities=['critical','high','medium','low','insight'] as const;
const reportTypes=['Smart Contract','Blockchain/DLT','Websites and Applications'] as const;
const severityTone:Record<string,'red'|'amber'|'blue'|'green'|'neutral'>={critical:'red',high:'amber',medium:'blue',low:'green',insight:'neutral'};
const capitalize=(value:string)=>value.charAt(0).toUpperCase()+value.slice(1);
// The sections of an Immunefi bug report, in submission order.
const descriptionSections=[
  {key:'brief',title:'Brief/Intro',hint:'A short summary of the bug and what happens if it is exploited in production.'},
  {key:'vulnerability_details',title:'Vulnerability Details',hint:'The root cause, with the relevant code snippets.'},
  {key:'impact_details',title:'Impact Details',hint:'What an attacker gains and what users or the protocol lose, with numbers where possible.'},
  {key:'references',title:'References',hint:'Links to the affected code, docs, and related issues.'},
] as const;
type SectionKey=typeof descriptionSections[number]['key']|'proof_of_concept'|'recommendation';

const pageSize=25;
// The list filters travel in the URL so the detail page can page through, and return to, the same filtered list.
const filterKeys=['search','severity','tag'] as const;
function filterQuery(params:URLSearchParams){const query=new URLSearchParams();for(const key of filterKeys){const value=params.get(key);if(value)query.set(key,value)}return query}
const withQuery=(path:string,query:URLSearchParams)=>query.toString()?path+'?'+query:path;

function SeverityBadge({severity}:{severity:string}){return <Badge tone={severityTone[severity]||'neutral'}>{capitalize(severity)}</Badge>}
const markdownComponents={a:({node:_node,href='',...props}:React.ComponentProps<'a'>&{node?:unknown})=>href.startsWith('/')?<Link to={href}>{props.children}</Link>:<a {...props} href={href} target="_blank" rel="noreferrer"/>};
function MarkdownBody({children,inline=false}:{children:string;inline?:boolean}){return children.trim()?<div className={inline?'markdown markdown-inline':'markdown'}><Markdown remarkPlugins={[remarkGfm]} components={markdownComponents}>{children}</Markdown></div>:<p className="muted-note">Not provided.</p>}

export function ReportsPanel({filter,addQuery}:{filter:string;addQuery:string}){
  const {data}=useApi<Page<VulnerabilityReport>>('/vulnerabilities?limit=10&'+filter);
  return <Panel title="Vulnerability reports" subtitle={`${data?.total??0} recorded`} action={<TextLink to={'/vulnerabilities/new?'+addQuery}>Add report</TextLink>}>{data?.items.length?<div className="stack-list">{data.items.map(report=><Link className="stack-row stack-link" to={'/vulnerabilities/'+report.id} key={report.id}><span className="stack-icon"><Bug size={17}/></span><div><strong>{report.title}</strong><span><SeverityBadge severity={report.severity}/> {report.reported_at?formatDate(report.reported_at,true):report.report_type}</span></div><ArrowUpRight size={16}/></Link>)}</div>:<Empty title="No reports yet"/>}</Panel>
}

export function Vulnerabilities(){
  const [params,setParams]=useSearchParams(),search=params.get('search')||'',severity=params.get('severity')||'',tag=params.get('tag')||'',offset=Number(params.get('offset'))||0;
  const update=(changes:Record<string,string|number>)=>setParams(current=>{const next=new URLSearchParams(current);for(const [key,value] of Object.entries(changes)){if(value)next.set(key,String(value));else next.delete(key)}return next},{replace:true});
  const setFilter=(key:typeof filterKeys[number])=>(e:React.ChangeEvent<HTMLInputElement|HTMLSelectElement>)=>update({[key]:e.target.value,offset:0});
  const setOffset=(value:number)=>update({offset:value});
  const detailPath=(id:number)=>withQuery('/vulnerabilities/'+id,filterQuery(params));
  const {data,error,loading}=useApi<Page<VulnerabilityReport>>('/vulnerabilities?offset='+offset+'&limit='+pageSize+'&search='+encodeURIComponent(search)+'&severity='+severity+'&tag='+encodeURIComponent(tag));
  const {data:tags}=useApi<string[]>('/vulnerabilities/tags');
  return <><PageTitle eyebrow="LEARNING LOG" title="Vulnerabilities" description="Reports of issues fixed in the repositories you follow, written up in Immunefi's report format." action={<Link className="button button-primary" to="/vulnerabilities/new"><Plus size={16}/>Add report</Link>}/>
    <div className="filter-bar"><div className="search-field"><Search size={18}/><input value={search} onChange={setFilter('search')} placeholder="Search reports..."/></div><select className="filter-select" aria-label="Severity" value={severity} onChange={setFilter('severity')}><option value="">All severities</option>{severities.map(item=><option key={item} value={item}>{capitalize(item)}</option>)}</select>{tags&&tags.length>0&&<select className="filter-select" aria-label="Tag" value={tag} onChange={setFilter('tag')}><option value="">All tags</option>{tags.map(item=><option key={item} value={item}>{item}</option>)}</select>}</div>
    {error&&<ErrorBanner message={error}/>}
    <Panel title="Reports" subtitle={`${data?.total??0} reports`} className="table-panel">{loading?<Loading/>:data?.items.length?<div className="data-table-wrap"><table className="data-table"><thead><tr><th>Report</th><th>Severity</th><th>Program</th><th>Repository</th><th>Reported</th><th></th></tr></thead><tbody>{data.items.map(report=><tr key={report.id}><td><div className="table-primary"><span className="table-icon table-icon-red"><Bug size={18}/></span><div><Link className="table-title report-title-cell" to={detailPath(report.id)}>{report.title}</Link><span className="table-subtitle">{report.tags.map(item=><span key={item} className="tag-chip">{item}</span>)}{report.report_type}{report.impacts[0]?' · '+report.impacts[0]:''}</span></div></div></td><td><SeverityBadge severity={report.severity}/></td><td className="muted-cell">{report.program_id?<Link to={'/programs/'+report.program_id}>{report.program_name}</Link>:'—'}</td><td className="muted-cell">{report.repository_id?<Link to={'/repositories/'+report.repository_id}>{report.repository_name}</Link>:'—'}</td><td className="muted-cell">{report.reported_at?formatDate(report.reported_at,true):'—'}</td><td><Link className="icon-button" to={detailPath(report.id)} aria-label={'View '+report.title}><ArrowUpRight size={17}/></Link></td></tr>)}</tbody></table></div>:<Empty title="No reports yet" description="Add a report to start your learning log." action={<Link className="button button-primary" to="/vulnerabilities/new"><Plus size={16}/>Add report</Link>}/>}</Panel>
    <Pagination total={data?.total??0} offset={offset} setOffset={setOffset}/>
  </>
}

export function VulnerabilityDetail(){
  const {id}=useParams(),[params]=useSearchParams(),navigate=useNavigate(),[deleteError,setDeleteError]=useState('');
  const filters=filterQuery(params),filtered=filters.toString()!=='';
  const {data:report,error,loading}=useApi<VulnerabilityReport>('/vulnerabilities/'+id);
  const {data:neighbors}=useApi<{previous:number|null;next:number|null;position:number|null;total:number}>(withQuery(`/vulnerabilities/${id}/neighbors`,filters));
  // Return to the list page that holds this report, with the same filters.
  const listQuery=new URLSearchParams(filters);if(neighbors?.position&&neighbors.position>pageSize)listQuery.set('offset',String(Math.floor((neighbors.position-1)/pageSize)*pageSize));
  const listPath=withQuery('/vulnerabilities',listQuery),detailPath=(other:number)=>withQuery('/vulnerabilities/'+other,filters);
  if(loading)return <Loading/>;if(error)return <ErrorBanner message={error}/>;if(!report)return null;
  async function remove(){if(!report||!confirm(`Delete "${report.title}"?`))return;try{await api('/vulnerabilities/'+report.id,{method:'DELETE'});navigate(neighbors?.next?detailPath(neighbors.next):neighbors?.previous?detailPath(neighbors.previous):listPath)}catch(err){setDeleteError(err instanceof Error?err.message:'Could not delete report')}}
  const stepButton=(target:number|null|undefined,label:string,icon:React.ReactNode,iconFirst:boolean)=>target?<Link className="button button-secondary" to={detailPath(target)}>{iconFirst&&icon}{label}{!iconFirst&&icon}</Link>:<span className="button button-secondary button-disabled" aria-disabled="true">{iconFirst&&icon}{label}{!iconFirst&&icon}</span>;
  return <><div className="report-nav"><Link className="back-link" to={listPath}><ArrowLeft size={16}/> Vulnerabilities{filtered&&<span className="report-nav-filter">{filterKeys.filter(key=>filters.get(key)).map(key=>key==='search'?`"${filters.get(key)}"`:key==='severity'?capitalize(filters.get(key)!):filters.get(key)).join(' · ')}</span>}</Link>
      <div className="report-nav-steps">{neighbors?.position&&<span className="report-nav-position">{neighbors.position} of {neighbors.total}</span>}{stepButton(neighbors?.previous,'Previous',<ChevronLeft size={16}/>,true)}{stepButton(neighbors?.next,'Next',<ChevronRight size={16}/>,false)}</div></div>
    <div className="detail-hero"><div className="detail-icon detail-red"><Bug size={28}/></div><div className="detail-title"><div className="eyebrow">REPORT #{report.id}</div><h1>{report.title}</h1><div className="detail-badges"><SeverityBadge severity={report.severity}/><Badge>{report.report_type}</Badge>{report.tags.map(item=><Link key={item} className="tag-chip" to={'/vulnerabilities?tag='+encodeURIComponent(item)}>{item}</Link>)}</div></div><div className="detail-actions"><Link className="button button-secondary" to={withQuery(`/vulnerabilities/${report.id}/edit`,filters)}><Pencil size={15}/>Edit</Link><button className="button button-secondary" onClick={remove}><Trash2 size={15}/>Delete</button></div></div>
    {deleteError&&<ErrorBanner message={deleteError}/>}
    <div className="detail-grid"><div className="detail-main">
      <Panel className="report-meta"><dl>
        <div><dt>Submitted on</dt><dd>{report.reported_at?formatDate(report.reported_at,true):'Not recorded'}</dd></div>
        <div><dt>Report type</dt><dd>{report.report_type}</dd></div>
        <div><dt>Report severity</dt><dd><SeverityBadge severity={report.severity}/></dd></div>
        <div className="report-meta-wide"><dt>Target</dt><dd className="break-all">{report.target?/^https?:\/\//.test(report.target)?<a href={report.target} target="_blank" rel="noreferrer">{report.target}</a>:report.target:'Not recorded'}</dd></div>
        <div className="report-meta-wide"><dt>Impacts</dt><dd>{report.impacts.length?<ul className="impact-list">{report.impacts.map(impact=><li key={impact}>{impact}</li>)}</ul>:'Not recorded'}</dd></div>
        {report.details.map((row,index)=><div className="report-meta-wide" key={index}><dt>{row.label}</dt><dd><MarkdownBody inline>{row.value}</MarkdownBody></dd></div>)}
      </dl></Panel>
      {report.extra_sections.filter(section=>section.placement==='before').map((section,index)=><Panel key={'b'+index} title={section.title} className="report-body"><section><MarkdownBody>{section.body}</MarkdownBody></section></Panel>)}
      <Panel title="Description" className="report-body">{descriptionSections.map(section=><section key={section.key}><h3>{section.title}</h3><MarkdownBody>{report[section.key]}</MarkdownBody></section>)}</Panel>
      <Panel title="Proof of Concept" className="report-body"><section><MarkdownBody>{report.proof_of_concept}</MarkdownBody></section></Panel>
      {report.recommendation.trim()&&<Panel title="Recommendation / Fix" className="report-body"><section><MarkdownBody>{report.recommendation}</MarkdownBody></section></Panel>}
      {report.extra_sections.filter(section=>section.placement==='after').map((section,index)=><Panel key={'a'+index} title={section.title} className="report-body"><section><MarkdownBody>{section.body}</MarkdownBody></section></Panel>)}
    </div><div className="detail-side">
      <Panel title="Fix and source"><div className="stack-list">
        {report.fix_url?<a className="stack-row stack-link" href={report.fix_url} target="_blank" rel="noreferrer"><span className="stack-icon"><GitPullRequest size={17}/></span><div><strong>Fix</strong><span className="break-all">{report.fix_url}</span></div><ExternalLink size={16}/></a>:<div className="stack-row"><span className="stack-icon"><GitPullRequest size={17}/></span><div><strong>Fix</strong><span>Not linked</span></div></div>}
        {report.source_url&&<a className="stack-row stack-link" href={report.source_url} target="_blank" rel="noreferrer"><span className="stack-icon"><ExternalLink size={17}/></span><div><strong>Original report</strong><span className="break-all">{report.source_url}</span></div><ExternalLink size={16}/></a>}
      </div></Panel>
      <Panel title="Linked to"><div className="stack-list">
        {report.program_id?<Link className="stack-row stack-link" to={'/programs/'+report.program_id}><div><strong>{report.program_name}</strong><span>Bounty program</span></div><ArrowUpRight size={16}/></Link>:<div className="stack-row"><div><strong>No program</strong></div></div>}
        {report.repository_id?<Link className="stack-row stack-link" to={'/repositories/'+report.repository_id}><div><strong>{report.repository_name}</strong><span>Repository</span></div><ArrowUpRight size={16}/></Link>:<div className="stack-row"><div><strong>No repository</strong></div></div>}
      </div></Panel>
    </div></div>
  </>
}

type Option={id:number;label:string};
function Picker({label,value,onChange,search}:{label:string;value:Option|null;onChange:(value:Option|null)=>void;search:(query:string)=>Promise<Option[]>}){
  const [query,setQuery]=useState(''),[options,setOptions]=useState<Option[]>([]),[open,setOpen]=useState(false);
  useEffect(()=>{if(!open)return;const timer=setTimeout(()=>{search(query).then(setOptions).catch(()=>setOptions([]))},200);return()=>clearTimeout(timer)},[query,open]);
  if(value)return <label>{label}<div className="picker-value"><span>{value.label}</span><button type="button" className="icon-button" onClick={()=>onChange(null)} aria-label={'Clear '+label}><X size={15}/></button></div></label>;
  return <label>{label} <span>optional</span><div className="picker"><input value={query} placeholder="Search..." onChange={e=>setQuery(e.target.value)} onFocus={()=>setOpen(true)} onBlur={()=>setTimeout(()=>setOpen(false),150)}/>{open&&options.length>0&&<ul className="picker-options">{options.map(option=><li key={option.id}><button type="button" onMouseDown={e=>e.preventDefault()} onClick={()=>{onChange(option);setQuery('');setOpen(false)}}>{option.label}</button></li>)}</ul>}</div></label>;
}
const searchPrograms=async(query:string)=>(await api<Page<Program>>('/programs?limit=8&search='+encodeURIComponent(query))).items.map(item=>({id:item.id,label:item.name}));
const searchRepositories=async(query:string)=>(await api<Page<Repository>>('/repositories?limit=8&search='+encodeURIComponent(query))).items.map(item=>({id:item.id,label:`${item.owner}/${item.name}`}));

const blank={title:'',severity:'high',report_type:'Smart Contract',target:'',impacts:[] as string[],brief:'',vulnerability_details:'',impact_details:'',references:'',proof_of_concept:'',recommendation:'',details:[] as {label:string;value:string}[],extra_sections:[] as ReportSection[],tags:[] as string[],fix_url:'',source_url:'',reported_at:''};
export function VulnerabilityForm(){
  const {id}=useParams(),[params]=useSearchParams(),navigate=useNavigate(),editing=Boolean(id),returnPath=withQuery(editing?'/vulnerabilities/'+id:'/vulnerabilities',filterQuery(params));
  const [form,setForm]=useState(blank),[program,setProgram]=useState<Option|null>(null),[repository,setRepository]=useState<Option|null>(null);
  const [impactInput,setImpactInput]=useState(''),[suggestions,setSuggestions]=useState<string[]>([]),[loading,setLoading]=useState(editing),[saving,setSaving]=useState(false),[error,setError]=useState('');
  useEffect(()=>{
    if(editing){api<VulnerabilityReport>('/vulnerabilities/'+id).then(report=>{setForm({...blank,...Object.fromEntries(Object.keys(blank).map(key=>[key,report[key as keyof VulnerabilityReport]??'']))} as typeof blank);setProgram(report.program_id?{id:report.program_id,label:report.program_name||'Program'}:null);setRepository(report.repository_id?{id:report.repository_id,label:report.repository_name||'Repository'}:null)}).catch(err=>setError(err.message)).finally(()=>setLoading(false));return}
    const programId=params.get('program'),repositoryId=params.get('repository');
    if(programId)api<Program>('/programs/'+programId).then(item=>setProgram({id:item.id,label:item.name})).catch(()=>{});
    if(repositoryId)api<Repository>('/repositories/'+repositoryId).then(item=>setRepository({id:item.id,label:`${item.owner}/${item.name}`})).catch(()=>{});
  },[id]);
  useEffect(()=>{setSuggestions([]);if(program)api<Program>('/programs/'+program.id).then(item=>setSuggestions((item.impacts||[]).map(impact=>impact.title))).catch(()=>{})},[program?.id]);
  const set=(key:keyof typeof blank)=>(e:React.ChangeEvent<HTMLInputElement|HTMLTextAreaElement|HTMLSelectElement>)=>setForm({...form,[key]:e.target.value});
  const [tagInput,setTagInput]=useState('');
  function addTags(){const values=tagInput.split(',').map(item=>item.trim()).filter(item=>item&&!form.tags.includes(item));if(values.length)setForm({...form,tags:[...form.tags,...values]});setTagInput('')}
  const setSection=(index:number,section:ReportSection)=>setForm(current=>({...current,extra_sections:current.extra_sections.map((other,position)=>position===index?section:other)}));
  const setDetail=(index:number,row:{label:string;value:string})=>setForm(current=>({...current,details:current.details.map((other,position)=>position===index?row:other)}));
  const toggleImpact=(impact:string)=>setForm(current=>({...current,impacts:current.impacts.includes(impact)?current.impacts.filter(item=>item!==impact):[...current.impacts,impact]}));
  function addImpact(){const value=impactInput.trim();if(value&&!form.impacts.includes(value))setForm({...form,impacts:[...form.impacts,value]});setImpactInput('')}
  async function save(event:React.FormEvent){event.preventDefault();setSaving(true);setError('');try{const body={...form,reported_at:form.reported_at||null,program_id:program?.id??null,repository_id:repository?.id??null};const saved=await api<VulnerabilityReport>(editing?'/vulnerabilities/'+id:'/vulnerabilities',{method:editing?'PUT':'POST',body:JSON.stringify(body)});navigate(withQuery('/vulnerabilities/'+saved.id,filterQuery(params)))}catch(err){setError(err instanceof Error?err.message:'Could not save report');setSaving(false)}}
  if(loading)return <Loading/>;
  const textSection=(key:SectionKey,title:string,hint:string,rows=6)=><label key={key} className="report-field">{title}<small>{hint} Markdown is supported.</small><textarea rows={rows} value={form[key]} onChange={set(key)}/></label>;
  return <><Link className="back-link" to={returnPath}><ArrowLeft size={16}/> {editing?'Report':'Vulnerabilities'}</Link>
    <PageTitle eyebrow="LEARNING LOG" title={editing?'Edit report':'Add a report'} description="Fill in the report the way it would be submitted on Immunefi."/>
    <form className="report-form" onSubmit={save}>
      <Panel title="Report" subtitle="What was found and where"><div className="form-grid">
        <label className="form-wide">Report title<input required value={form.title} onChange={set('title')} placeholder="e.g. Reentrancy in Vault.withdraw lets an attacker drain deposits"/></label>
        <label>Report type<select value={form.report_type} onChange={set('report_type')}>{reportTypes.map(item=><option key={item}>{item}</option>)}</select></label>
        <label>Severity<select value={form.severity} onChange={set('severity')}>{severities.map(item=><option key={item} value={item}>{capitalize(item)}</option>)}</select></label>
        <label className="form-wide">Target <span>the affected asset</span><input value={form.target} onChange={set('target')} placeholder="https://github.com/org/repo/blob/main/src/Vault.sol"/></label>
        <div className="form-wide impacts-field"><span className="field-label">Tags <small>e.g. the chain or project, like Sei or NEAR</small></span>
          {form.tags.length>0&&<div className="impact-options">{form.tags.map(item=><button type="button" key={item} className="impact-chip selected" onClick={()=>setForm({...form,tags:form.tags.filter(other=>other!==item)})}>{item} <X size={12}/></button>)}</div>}
          <div className="inline-add"><input value={tagInput} onChange={e=>setTagInput(e.target.value)} onKeyDown={e=>{if(e.key==='Enter'){e.preventDefault();addTags()}}} placeholder="Add tags, separated by commas"/><button type="button" className="button button-secondary" onClick={addTags}>Add</button></div>
        </div>
        <Picker label="Program" value={program} onChange={setProgram} search={searchPrograms}/>
        <Picker label="Repository" value={repository} onChange={setRepository} search={searchRepositories}/>
        <div className="form-wide impacts-field"><span className="field-label">Impacts</span>
          {suggestions.length>0&&<><small>In scope for {program?.label}. Click to select.</small><div className="impact-options">{suggestions.map(impact=><button type="button" key={impact} className={'impact-chip '+(form.impacts.includes(impact)?'selected':'')} onClick={()=>toggleImpact(impact)}>{impact}</button>)}</div></>}
          {form.impacts.filter(impact=>!suggestions.includes(impact)).length>0&&<div className="impact-options">{form.impacts.filter(impact=>!suggestions.includes(impact)).map(impact=><button type="button" key={impact} className="impact-chip selected" onClick={()=>toggleImpact(impact)}>{impact} <X size={12}/></button>)}</div>}
          <div className="inline-add"><input value={impactInput} onChange={e=>setImpactInput(e.target.value)} onKeyDown={e=>{if(e.key==='Enter'){e.preventDefault();addImpact()}}} placeholder="Add an impact, e.g. Direct theft of any user funds"/><button type="button" className="button button-secondary" onClick={addImpact}>Add</button></div>
        </div>
      </div></Panel>
      <Panel title="Description" subtitle="Bug description, in Immunefi's template"><div className="form-stack">{descriptionSections.map(section=>textSection(section.key,section.title,section.hint))}</div></Panel>
      <Panel title="Proof of Concept" subtitle="Steps or code that show the bug working"><div className="form-stack">{textSection('proof_of_concept','Proof of Concept','A runnable test or step-by-step exploit.',10)}</div></Panel>
      <Panel title="Recommendation / Fix" subtitle="How it was or should be fixed"><div className="form-stack">{textSection('recommendation','Recommendation / Fix','The fix that was applied, and anything still open.',6)}</div></Panel>
"      <Panel title="Extra sections" subtitle="Sections beyond Immunefi's template, e.g. TL;DR, Background or Lessons"><div className="form-stack">
        {form.extra_sections.map((section,index)=><div className="section-field" key={index}><div className="section-field-head"><input aria-label="Section title" placeholder="Section title" value={section.title} onChange={e=>setSection(index,{...section,title:e.target.value})}/><select aria-label="Placement" value={section.placement} onChange={e=>setSection(index,{...section,placement:e.target.value as ReportSection['placement']})}><option value="before">Before the description</option><option value="after">After the report</option></select><button type="button" className="icon-button" onClick={()=>setForm({...form,extra_sections:form.extra_sections.filter((_,other)=>other!==index)})} aria-label="Remove section"><X size={15}/></button></div><textarea rows={5} aria-label="Section body" placeholder="Markdown" value={section.body} onChange={e=>setSection(index,{...section,body:e.target.value})}/></div>)}
        <div><button type="button" className="button button-secondary" onClick={()=>setForm({...form,extra_sections:[...form.extra_sections,{title:'',body:'',placement:'after'}]})}><Plus size={15}/>Add section</button></div>
      </div></Panel>
      <Panel title="Additional details" subtitle="Extra rows shown with the report details, e.g. Attacker or Affected releases"><div className="form-stack">
        {form.details.map((row,index)=><div className="detail-row-field" key={index}><input aria-label="Label" placeholder="Label" value={row.label} onChange={e=>setDetail(index,{...row,label:e.target.value})}/><textarea aria-label="Value" rows={2} placeholder="Value (Markdown)" value={row.value} onChange={e=>setDetail(index,{...row,value:e.target.value})}/><button type="button" className="icon-button" onClick={()=>setForm({...form,details:form.details.filter((_,other)=>other!==index)})} aria-label="Remove row"><X size={15}/></button></div>)}
        <div><button type="button" className="button button-secondary" onClick={()=>setForm({...form,details:[...form.details,{label:'',value:''}]})}><Plus size={15}/>Add row</button></div>
      </div></Panel>
      <Panel title="Fix and source" subtitle="Where it was fixed and where you found it"><div className="form-grid">
        <label className="form-wide">Fix <span>commit or pull request URL</span><input type="url" value={form.fix_url} onChange={set('fix_url')} placeholder="https://github.com/org/repo/pull/123"/></label>
        <label className="form-wide">Original report <span>optional</span><input type="url" value={form.source_url} onChange={set('source_url')} placeholder="https://..."/></label>
        <label>Submitted on <span>optional</span><input type="date" value={form.reported_at} onChange={set('reported_at')}/></label>
      </div></Panel>
      {error&&<ErrorBanner message={error}/>}
      <div className="form-actions"><Link className="button button-secondary" to={returnPath}>Cancel</Link><button className="button button-primary" disabled={saving}>{saving?'Saving...':editing?'Save changes':'Add report'}</button></div>
    </form>
  </>
}
