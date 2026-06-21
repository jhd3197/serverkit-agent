import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar.jsx';

export default function Shell() {
    return (
        <div className="shell">
            <Sidebar />
            <main className="shell__main">
                <Outlet />
            </main>
        </div>
    );
}
