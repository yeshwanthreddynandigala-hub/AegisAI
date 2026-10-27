import React from 'react';
import {
  formatLocalDateTime,
  formatUtcDateTime,
  isHistoricalDemoEvent
} from '../utils/dateUtils';

interface TimestampDisplayProps {
  timestamp: string | Date | null | undefined;
  sessionId?: string;
  taskId?: string;
  showBadge?: boolean;
  className?: string;
}

export const TimestampDisplay: React.FC<TimestampDisplayProps> = ({
  timestamp,
  sessionId,
  taskId,
  showBadge = true,
  className = ''
}) => {
  if (!timestamp) return <span className="text-slate-500">N/A</span>;

  const localFormatted = formatLocalDateTime(timestamp);
  const utcFormatted = formatUtcDateTime(timestamp);
  const isHistorical = isHistoricalDemoEvent(timestamp, sessionId, taskId);

  return (
    <div className={`inline-flex flex-col ${className}`} title={`UTC Reference: ${utcFormatted}`}>
      <div className="flex items-center space-x-1.5">
        <span className="font-mono text-slate-300 whitespace-nowrap">{localFormatted}</span>
        {showBadge && (
          isHistorical ? (
            <span
              className="px-1.5 py-0.2 rounded text-[9px] font-mono tracking-wider uppercase bg-purple-500/10 text-purple-400 border border-purple-500/20 whitespace-nowrap"
              title="Synthetic benchmark baseline event from historical test suite"
            >
              HISTORICAL DEMO
            </span>
          ) : (
            <span
              className="px-1.5 py-0.2 rounded text-[9px] font-mono tracking-wider uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 whitespace-nowrap"
              title="Live agent execution event from current session"
            >
              LIVE
            </span>
          )
        )}
      </div>
      <span className="text-[10px] font-mono text-slate-500 whitespace-nowrap">
        {utcFormatted}
      </span>
    </div>
  );
};
