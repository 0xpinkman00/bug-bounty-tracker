import {createRoot} from 'react-dom/client';
import {BrowserRouter,Navigate,Route,Routes} from 'react-router-dom';
import {Layout} from './Layout';
import {Dashboard} from './Dashboard';
import {Activity} from './Activity';
import {Programs,ProgramDetail} from './Programs';
import {Repositories,RepositoryDetail} from './Repositories';
import {Settings} from './Settings';
import './index.css';
function App(){return <BrowserRouter><Layout><Routes><Route path="/" element={<Dashboard/>}/><Route path="/activity" element={<Activity/>}/><Route path="/programs" element={<Navigate to="/programs/immunefi" replace/>}/><Route path="/programs/immunefi" element={<Programs key="immunefi" group="immunefi"/>}/><Route path="/programs/hackenproof" element={<Programs key="hackenproof" group="hackenproof"/>}/><Route path="/programs/other" element={<Programs key="other" group="other"/>}/><Route path="/programs/:id" element={<ProgramDetail/>}/><Route path="/repositories" element={<Repositories/>}/><Route path="/repositories/:id" element={<RepositoryDetail/>}/><Route path="/releases" element={<Navigate to="/repositories" replace/>}/><Route path="/sources/*" element={<Navigate to="/programs/immunefi" replace/>}/><Route path="/settings" element={<Settings/>}/></Routes></Layout></BrowserRouter>}
createRoot(document.getElementById('root')!).render(<App/>);
