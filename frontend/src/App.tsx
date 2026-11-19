import { useState } from 'react'
import heroImg from './assets/hero.png'
import reactLogo from './assets/react.svg'
import viteLogo from './assets/vite.svg'
import './App.css'
import MetricCard from './pages/Dashboard'

function App() {
  const [count, setCount] = useState(0)

  return (
    <div>
      <h1>NIDS Dashboard</h1>
      <MetricCard 
      title='Total Packets'
      value={12450}
      description='Packets Captured'
      />
      
    </div>
  )
}

export default App
