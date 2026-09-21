import {createRoot} from 'react-dom/client';
import {BrowserRouter,Route,Routes} from 'react-router-dom';
import {Layout} from './Layout';
import {Dashboard} from './Dashboard';
import {Activity} from './Activity';
import {Programs,ProgramDetail} from './Programs';
import {Repositories,RepositoryDetail} from './Repositories';
import {Releases} from './Releases';
import {Sources,SourceDetail} from './Sources';
import {Settings} from './Settings';
import './index.css';
function App(){return <BrowserRouter><Layout><Routes><Route path="/" element={<Dashboard/>}/><Route path="/activity" element={<Activity/>}/><Route path="/programs" element={<Programs/>}/><Route path="/programs/:id" element={<ProgramDetail/>}/><Route path="/repositories" element={<Repositories/>}/><Route path="/repositories/:id" element={<RepositoryDetail/>}/><Route path="/releases" element={<Releases/>}/><Route path="/sources" element={<Sources/>}/><Route path="/sources/:name" element={<SourceDetail/>}/><Route path="/settings" element={<Settings/>}/></Routes></Layout></BrowserRouter>}
createRoot(document.getElementById('root')!).render(<App/>);
