import win32evtlog

server = 'localhost' # name of the target computer to get event logs
logtype = 'Security'
handle = win32evtlog.OpenEventLog(server,logtype)
flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
total = win32evtlog.GetNumberOfEventLogRecords(handle)
print(total)
f = open("logevents.txt", "w")

while True:
    events = win32evtlog.ReadEventLog(handle, flags,0)

    event_occurred = False
    while not event_occurred:
        for event in events:
            if event.EventID == 4656:
                f.write('Event occurred')
                event_occurred = True



    # events_list = [event for event in events if event.EventID == 4656]
    # if events_list:
    #     for event in events_list:
    #         f.write('Event Category: ' + str (events_list[0].EventCategory) + "\n")
    #         f.write('Time Generated: ' + str(events_list[0].TimeGenerated) + "\n")
    #         f.write ('Source Name: ' + str(events_list[0].SourceName) + "\n")
    #         f.write('Event ID: ' + str(events_list[0].EventID) + "\n")
    #         f.write('Event Type: ' + str(events_list[0].EventType) + "\n")
    #         data = events_list[0].StringInserts
    #         if data:
    #             f.write('Event Data:')
    #             for msg in data:
    #                 f.write(msg)
    #         f.write('\n---------------------------------------------------------------------\n')
    #         f.write('NEXT EVENT\n')
    #         f.write('---------------------------------------------------------------------\n')
    #         break
